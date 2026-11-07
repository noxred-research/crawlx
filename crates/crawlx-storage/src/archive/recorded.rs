//! Bounded read-only archive projection of existing tenant-owned traffic artifact references.

use crate::codec::{digest, get};
use crate::error::db;
use crate::Pg;
use crawlx_core::{ArtifactId, ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};

/// One chronological persisted traffic event. Headers and status are not reconstructed as wire data.
#[derive(Clone, Debug)]
pub struct RecordedTraffic {
    /// Persisted chronological event identifier.
    pub event_id: i64,
    /// Privacy-approved recorded target, absent when not retained.
    pub url: Option<String>,
    /// Real event capture date.
    pub captured_at: Timestamp,
    /// Retained request representation, when still live in this run.
    pub request_body: Option<ArtifactRef>,
    /// Retained response representation, when still live in this run.
    pub response_body: Option<ArtifactRef>,
}

fn artifact(id: Option<uuid::Uuid>, hash: Option<Vec<u8>>) -> Result<Option<ArtifactRef>, StoreError> {
    match (id, hash) {
        (Some(id), Some(hash)) => Ok(Some(ArtifactRef {
            id: ArtifactId(id),
            digest: digest(&hash)?,
        })),
        _ => Ok(None),
    }
}

/// Read at most `max` chronological events, enforcing tenant ownership in SQL as well as RLS scope.
///
/// No body bytes live in this projection. Missing/deleted references remain missing, never refetched.
///
/// # Errors
/// Returns storage errors or a conflict when the bounded event count would be exceeded.
pub async fn traffic(
    pg: &Pg,
    tenant: TenantId,
    run: CrawlRunId,
    max: u32,
) -> Result<Vec<RecordedTraffic>, StoreError> {
    let rows = traffic_after(pg, tenant, run, 0, i64::from(max) + 1).await?;
    if rows.len() as u64 > u64::from(max) {
        return Err(StoreError::Conflict(
            "archive traffic event bound exceeded".into(),
        ));
    }
    Ok(rows)
}

/// Read at most 64 real events strictly after `after`, without loading the collection.
///
/// # Errors
/// Returns storage errors, an invalid page size, or an ordinal outside PostgreSQL bigint.
pub async fn traffic_keyset(
    pg: &Pg,
    tenant: TenantId,
    run: CrawlRunId,
    after: u64,
    limit: u32,
) -> Result<Vec<RecordedTraffic>, StoreError> {
    if !(1..=64).contains(&limit) {
        return Err(StoreError::Conflict(
            "archive traffic keyset limit must be 1..64".into(),
        ));
    }
    let after = i64::try_from(after)
        .map_err(|_| StoreError::Conflict("archive traffic ordinal exceeds bigint".into()))?;
    traffic_after(pg, tenant, run, after, i64::from(limit)).await
}

async fn traffic_after(
    pg: &Pg,
    tenant: TenantId,
    run: CrawlRunId,
    after: i64,
    limit: i64,
) -> Result<Vec<RecordedTraffic>, StoreError> {
    let rows = sqlx::query(
        "SELECT t.event_id, t.occurred_at, t.url_redacted, \
           req.artifact_id AS request_id, req.content_digest AS request_digest, \
           resp.artifact_id AS response_id, resp.content_digest AS response_digest \
         FROM traffic_events t JOIN crawl_runs r ON r.run_id = t.run_id \
         LEFT JOIN artifacts req ON req.artifact_id = t.request_body_artifact_id \
           AND req.run_id = t.run_id AND req.tenant_id = r.tenant_id AND req.deleted_at IS NULL \
         LEFT JOIN artifacts resp ON resp.artifact_id = t.body_artifact_id \
           AND resp.run_id = t.run_id AND resp.tenant_id = r.tenant_id AND resp.deleted_at IS NULL \
         WHERE t.run_id = $1 AND r.tenant_id = $2 AND t.event_id > $3 ORDER BY t.event_id LIMIT $4",
    )
    .bind(run.0)
    .bind(tenant.0)
    .bind(after)
    .bind(limit)
    .fetch_all(&pg.pool)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            Ok(RecordedTraffic {
                event_id: get(row, "event_id")?,
                url: get(row, "url_redacted")?,
                captured_at: get(row, "occurred_at")?,
                request_body: artifact(get(row, "request_id")?, get(row, "request_digest")?)?,
                response_body: artifact(get(row, "response_id")?, get(row, "response_digest")?)?,
            })
        })
        .collect()
}
