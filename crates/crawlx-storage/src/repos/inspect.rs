//! [`InspectRepo`]: typed reads of `network_epochs`, navigation `crawl_events` and
//! `transitions` for `crawlx inspect` and `crawlx replay`. SQL lives only here;
//! the CLI shapes these rows into its output.

#![deny(clippy::disallowed_methods)]

use crate::backend::PgBackend;
use crate::codec::{conv, parse_label};
use crate::sql::{SqlRow, Stmt};
use crate::store::Store;
use crate::tenant::Tenancy;
use crawlx_core::traffic::TrustLane;
use crawlx_core::{
    ActionId, CrawlRunId, NetworkEpochId, SessionId, StateId, StoreError, Timestamp, TransitionId,
};

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
pub struct InspectRepo<B: Tenancy = PgBackend> {
    store: Store<B>,
}

fn epoch_from_row<R: SqlRow>(r: &R) -> Result<EpochRow, StoreError> {
    Ok(EpochRow {
        epoch: NetworkEpochId(r.uuid("epoch_id")?),
        session: SessionId(r.uuid("session_id")?),
        action: r.opt_uuid("action_id")?.map(ActionId),
        lane: parse_label(&r.text("lane")?)?,
        started_at: r.ts("started_at")?,
        settled_at: r.opt_ts("settled_at")?,
        request_count: conv(r.i32("request_count")?, "request_count")?,
        unique_operations: conv(r.i32("unique_operations")?, "unique_operations")?,
        settle_timeout: r.bool("settle_timeout")?,
    })
}

fn transition_from_row<R: SqlRow>(r: &R) -> Result<TransitionRow, StoreError> {
    Ok(TransitionRow {
        id: TransitionId(r.uuid("transition_id")?),
        session: SessionId(r.uuid("session_id")?),
        before_state: StateId(r.uuid("before_state_id")?),
        action: ActionId(r.uuid("action_id")?),
        network_epoch: r.opt_uuid("network_epoch_id")?.map(NetworkEpochId),
        after_state: r.opt_uuid("after_state_id")?.map(StateId),
        lane: parse_label(&r.text("lane")?)?,
        settle_report: r.json("settle_report")?,
    })
}

impl<B: Tenancy> InspectRepo<B> {
    /// Introspection reads over `store`.
    #[must_use]
    pub const fn new(store: Store<B>) -> Self {
        Self { store }
    }

    /// Every network epoch of `run` in `(started_at, epoch_id)` order.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails, a counter does not fit `u32` or a lane label is unknown.
    pub async fn epochs(&self, run: CrawlRunId) -> Result<Vec<EpochRow>, StoreError> {
        let _timer = self.store.query_timer("inspect.epochs");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT epoch_id, session_id, action_id, lane::text AS lane, started_at, settled_at, request_count, \
             unique_operations, settle_timeout FROM network_epochs WHERE run_id = $1{} ORDER BY started_at, epoch_id",
            scope.and("network_epochs", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
        rows.iter().map(epoch_from_row).collect()
    }

    /// The `navigation` audit events of `run` in `seq` order.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a sequence number does not fit `u64`.
    pub async fn navigations(&self, run: CrawlRunId) -> Result<Vec<NavigationEvent>, StoreError> {
        let _timer = self.store.query_timer("inspect.navigations");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT seq, payload, created_at FROM crawl_events WHERE run_id = $1 AND type = 'navigation'{} ORDER BY seq",
            scope.and("crawl_events", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
        let (tenant, zdr) = self.store.owned_privacy_scope(&scope, run).await?;
        let mut events = Vec::with_capacity(rows.len());
        for r in &rows {
            let seq = conv(r.i64("seq")?, "seq")?;
            let payload = if zdr {
                let (_, payload): (String, serde_json::Value) = self
                    .store
                    .ephemeral_get(tenant, run, i64::MIN + 1, &format!("_event:{seq}"))
                    .await?;
                payload
            } else {
                r.json("payload")?
            };
            events.push(NavigationEvent {
                seq,
                at: r.ts("created_at")?,
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
        let _timer = self.store.query_timer("inspect.transitions");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT transition_id, session_id, before_state_id, action_id, network_epoch_id, after_state_id, \
             lane::text AS lane, settle_report FROM transitions WHERE run_id = $1{} ORDER BY created_at, transition_id",
            scope.and("transitions", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
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
        let _timer = self.store.query_timer("inspect.transition_action");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT action_id FROM transitions WHERE transition_id = $1 AND run_id = $2{}",
            scope.and("transitions", "", 3)?
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(transition.0).uuid(run.0))
            .fetch_optional_pool(&self.store.pool)
            .await?;
        row.map(|r| Ok(ActionId(r.uuid("action_id")?))).transpose()
    }
}
