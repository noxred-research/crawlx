//! [`TrailReads`]: the PostgreSQL reads the trail verifier (`crawlx-bench verify-trail`)
//! needs beyond the repository traits: artifact-index digests, the
//! attribution columns of `traffic_events` and the ids of `safety_decisions` rows.
//! SQL lives only here; the verifier is pure over these rows.

use crate::codec::{conv, get};
use crate::error::db;
use crate::pg::Pg;
use crawlx_core::hash::Digest;
use crawlx_core::traffic::UnattributedReason;
use crawlx_core::{CrawlRunId, NetworkEpochId, SafetyDecisionId, StoreError};
use std::collections::BTreeSet;

/// The attribution columns of one `traffic_events` row.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct TrafficAttributionRow {
    /// `traffic_events.event_id` (persisted order within the run).
    pub event_id: u64,
    /// Epoch the row is attributed to; `None` only with a reason (migration 0010).
    pub epoch: Option<NetworkEpochId>,
    /// Why the row has no epoch; `None` when attributed.
    pub unattributed_reason: Option<UnattributedReason>,
}

/// Verifier reads over `pg`.
#[derive(Clone, Debug)]
pub struct TrailReads {
    pg: Pg,
}

impl TrailReads {
    /// Reads over `pg`.
    #[must_use]
    pub const fn new(pg: Pg) -> Self {
        Self { pg }
    }

    /// Content digests of every live artifact of `run` (`artifacts.deleted_at IS NULL`).
    ///
    /// # Errors
    /// Query failure, or a stored digest that is not 32 bytes.
    pub async fn artifact_digests(&self, run: CrawlRunId) -> Result<BTreeSet<Digest>, StoreError> {
        let rows =
            sqlx::query("SELECT content_digest FROM artifacts WHERE run_id = $1 AND deleted_at IS NULL")
                .bind(run.0)
                .fetch_all(&self.pg.pool)
                .await
                .map_err(db)?;
        let mut digests = BTreeSet::new();
        for r in &rows {
            let bytes: Vec<u8> = get(r, "content_digest")?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| StoreError::Serialization("artifact digest is not 32 bytes".to_owned()))?;
            digests.insert(Digest(arr));
        }
        Ok(digests)
    }

    /// Attribution columns of every `traffic_events` row of `run` in `event_id` order.
    ///
    /// # Errors
    /// Query failure or an unknown stored reason.
    pub async fn traffic_attribution(
        &self,
        run: CrawlRunId,
    ) -> Result<Vec<TrafficAttributionRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT event_id, epoch_id, unattributed_reason FROM traffic_events WHERE run_id = $1 ORDER BY event_id",
        )
        .bind(run.0)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let reason = match get::<Option<String>>(r, "unattributed_reason")? {
                Some(s) => Some(
                    serde_json::from_value::<UnattributedReason>(serde_json::Value::String(s.clone()))
                        .map_err(|_| {
                            StoreError::Serialization(format!("unknown unattributed reason {s:?}"))
                        })?,
                ),
                None => None,
            };
            out.push(TrafficAttributionRow {
                event_id: conv(get::<i64>(r, "event_id")?, "event_id")?,
                epoch: get::<Option<uuid::Uuid>>(r, "epoch_id")?.map(NetworkEpochId),
                unattributed_reason: reason,
            });
        }
        Ok(out)
    }

    /// Ids of every `safety_decisions` row of `run`.
    ///
    /// # Errors
    /// Query failure.
    pub async fn safety_decision_ids(
        &self,
        run: CrawlRunId,
    ) -> Result<BTreeSet<SafetyDecisionId>, StoreError> {
        let rows = sqlx::query("SELECT decision_id FROM safety_decisions WHERE run_id = $1")
            .bind(run.0)
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| Ok(SafetyDecisionId(get(r, "decision_id")?)))
            .collect()
    }
}
