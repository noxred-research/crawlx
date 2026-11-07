//! [`InspectRepo`]: typed reads of `network_epochs`, navigation `crawl_events` and
//! `transitions` for `crawlx inspect` and `crawlx replay`. SQL lives only here;
//! the CLI shapes these rows into its output.

use crate::codec::{conv, get, parse_label};
use crate::error::db;
use crate::pg::Pg;
use crawlx_core::traffic::TrustLane;
use crawlx_core::{
    ActionId, CrawlRunId, NetworkEpochId, SessionId, StateId, StoreError, Timestamp, TransitionId,
};
use sqlx::postgres::PgRow;

/// One `network_epochs` row.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct EpochRow {
    /// `network_epochs.epoch_id`.
    pub epoch: NetworkEpochId,
    /// Session that owned the epoch.
    pub session: SessionId,
    /// Action the epoch was opened for; `None` for navigations and other action-less epochs.
    pub action: Option<ActionId>,
    /// Lane of the epoch (equal to the owning action's lane, migration 0008).
    pub lane: TrustLane,
    /// When the epoch opened.
    pub started_at: Timestamp,
    /// When the epoch settled; `None` while open.
    pub settled_at: Option<Timestamp>,
    /// Requests observed in the epoch.
    pub request_count: u32,
    /// Distinct `(method, route)` operations observed in the epoch.
    pub unique_operations: u32,
    /// The settle criterion timed out before the epoch went quiet.
    pub settle_timeout: bool,
}

/// One `crawl_events` row of type `navigation`, payload as the worker wrote it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct NavigationEvent {
    /// `crawl_events.seq`.
    pub seq: u64,
    /// When the event was recorded.
    pub at: Timestamp,
    /// The audit payload (`url`, `finalUrl`, `status`, `epoch`, `settle`, `blockedByEgress`, ...).
    pub payload: serde_json::Value,
}

/// One `transitions` row.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct TransitionRow {
    /// `transitions.transition_id`.
    pub id: TransitionId,
    /// Session that executed the action.
    pub session: SessionId,
    /// State the action started from.
    pub before_state: StateId,
    /// The executed action.
    pub action: ActionId,
    /// Network epoch of the action; `None` when none was recorded.
    pub network_epoch: Option<NetworkEpochId>,
    /// State the action led to; `None` when the observation did not produce one.
    pub after_state: Option<StateId>,
    /// Lane of the action.
    pub lane: TrustLane,
    /// The settle report as stored.
    pub settle_report: serde_json::Value,
}

/// Read-only run introspection over `network_epochs`, navigation events and `transitions`.
#[derive(Clone, Debug)]
pub struct InspectRepo {
    pg: Pg,
}

fn epoch_from_row(r: &PgRow) -> Result<EpochRow, StoreError> {
    Ok(EpochRow {
        epoch: NetworkEpochId(get(r, "epoch_id")?),
        session: SessionId(get(r, "session_id")?),
        action: get::<Option<uuid::Uuid>>(r, "action_id")?.map(ActionId),
        lane: parse_label(&get::<String>(r, "lane")?)?,
        started_at: get(r, "started_at")?,
        settled_at: get(r, "settled_at")?,
        request_count: conv(get::<i32>(r, "request_count")?, "request_count")?,
        unique_operations: conv(get::<i32>(r, "unique_operations")?, "unique_operations")?,
        settle_timeout: get(r, "settle_timeout")?,
    })
}

fn transition_from_row(r: &PgRow) -> Result<TransitionRow, StoreError> {
    Ok(TransitionRow {
        id: TransitionId(get(r, "transition_id")?),
        session: SessionId(get(r, "session_id")?),
        before_state: StateId(get(r, "before_state_id")?),
        action: ActionId(get(r, "action_id")?),
        network_epoch: get::<Option<uuid::Uuid>>(r, "network_epoch_id")?.map(NetworkEpochId),
        after_state: get::<Option<uuid::Uuid>>(r, "after_state_id")?.map(StateId),
        lane: parse_label(&get::<String>(r, "lane")?)?,
        settle_report: get(r, "settle_report")?,
    })
}

impl InspectRepo {
    /// Introspection reads over `pg`.
    #[must_use]
    pub const fn new(pg: Pg) -> Self {
        Self { pg }
    }

    /// Every network epoch of `run` in `(started_at, epoch_id)` order.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails, a counter does not fit `u32` or a lane label is unknown.
    pub async fn epochs(&self, run: CrawlRunId) -> Result<Vec<EpochRow>, StoreError> {
        let _timer = self.pg.query_timer("inspect.epochs");
        let rows = sqlx::query(
            "SELECT epoch_id, session_id, action_id, lane::text AS lane, started_at, settled_at, request_count, \
             unique_operations, settle_timeout FROM network_epochs WHERE run_id = $1 ORDER BY started_at, epoch_id",
        )
        .bind(run.0)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        rows.iter().map(epoch_from_row).collect()
    }

    /// The `navigation` audit events of `run` in `seq` order.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a sequence number does not fit `u64`.
    pub async fn navigations(&self, run: CrawlRunId) -> Result<Vec<NavigationEvent>, StoreError> {
        let _timer = self.pg.query_timer("inspect.navigations");
        let rows = sqlx::query(
            "SELECT seq, payload, created_at FROM crawl_events WHERE run_id = $1 AND type = 'navigation' ORDER BY seq",
        )
        .bind(run.0)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        let (tenant, zdr) = self.pg.privacy_scope(run).await?;
        let mut events = Vec::with_capacity(rows.len());
        for r in &rows {
            let seq = conv(get::<i64>(r, "seq")?, "seq")?;
            let payload = if zdr {
                let (_, payload): (String, serde_json::Value) = self
                    .pg
                    .ephemeral_get(tenant, run, i64::MIN + 1, &format!("_event:{seq}"))
                    .await?;
                payload
            } else {
                get(r, "payload")?
            };
            events.push(NavigationEvent {
                seq,
                at: get(r, "created_at")?,
                payload,
            });
        }
        Ok(events)
    }

    /// Every transition of `run` in `(created_at, transition_id)` order.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a lane label is unknown.
    pub async fn transitions(&self, run: CrawlRunId) -> Result<Vec<TransitionRow>, StoreError> {
        let _timer = self.pg.query_timer("inspect.transitions");
        let rows = sqlx::query(
            "SELECT transition_id, session_id, before_state_id, action_id, network_epoch_id, after_state_id, \
             lane::text AS lane, settle_report FROM transitions WHERE run_id = $1 ORDER BY created_at, transition_id",
        )
        .bind(run.0)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        rows.iter().map(transition_from_row).collect()
    }

    /// The action that produced `transition` in `run`; `None` when the transition is not
    /// part of the run.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn transition_action(
        &self,
        run: CrawlRunId,
        transition: TransitionId,
    ) -> Result<Option<ActionId>, StoreError> {
        let _timer = self.pg.query_timer("inspect.transition_action");
        let id: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT action_id FROM transitions WHERE transition_id = $1 AND run_id = $2")
                .bind(transition.0)
                .bind(run.0)
                .fetch_optional(&self.pg.pool)
                .await
                .map_err(db)?;
        Ok(id.map(ActionId))
    }
}
