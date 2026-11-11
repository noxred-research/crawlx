//! [`TrailReads`]: the reads the trail verifier (`crawlx-bench verify-trail`)
//! needs beyond the repository traits: artifact-index digests, the
//! attribution columns of `traffic_events` and the ids of `safety_decisions` rows.
//! SQL lives only here; the verifier is pure over these rows.

#![deny(clippy::disallowed_methods)]

use crate::backend::PgBackend;
use crate::codec::conv;
use crate::sql::{SqlRow, Stmt};
use crate::store::Store;
use crate::tenant::Tenancy;
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

/// Verifier reads over a [`Store`].
#[derive(Clone, Debug)]
pub struct TrailReads<B: Tenancy = PgBackend> {
    store: Store<B>,
}

impl<B: Tenancy> TrailReads<B> {
    /// Reads over `store`.
    #[must_use]
    pub const fn new(store: Store<B>) -> Self {
        Self { store }
    }

    /// Content digests of every live artifact of `run` (`artifacts.deleted_at IS NULL`).
    ///
    /// # Errors
    /// Query failure, or a stored digest that is not 32 bytes.
    pub async fn artifact_digests(&self, run: CrawlRunId) -> Result<BTreeSet<Digest>, StoreError> {
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT content_digest FROM artifacts WHERE run_id = $1 AND deleted_at IS NULL{}",
            scope.and("artifacts", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
        let mut digests = BTreeSet::new();
        for r in &rows {
            let bytes = r.bytes("content_digest")?;
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
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT event_id, epoch_id, unattributed_reason FROM traffic_events WHERE run_id = $1{} ORDER BY event_id",
            scope.and("traffic_events", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let reason = match r.opt_text("unattributed_reason")? {
                Some(s) => Some(
                    serde_json::from_value::<UnattributedReason>(serde_json::Value::String(s.clone()))
                        .map_err(|_| {
                            StoreError::Serialization(format!("unknown unattributed reason {s:?}"))
                        })?,
                ),
                None => None,
            };
            out.push(TrafficAttributionRow {
                event_id: conv(r.i64("event_id")?, "event_id")?,
                epoch: r.opt_uuid("epoch_id")?.map(NetworkEpochId),
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
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT decision_id FROM safety_decisions WHERE run_id = $1{}",
            scope.and("safety_decisions", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
        rows.iter()
            .map(|r| Ok(SafetyDecisionId(r.uuid("decision_id")?)))
            .collect()
    }
}
