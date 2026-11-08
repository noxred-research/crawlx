//! [`TrustedCorpus`]: the only read path for coverage and traffic consumers.
//!
//! Every query here carries the lane predicate in SQL; there is no accessor that
//! returns rows of both lanes without a [`LaneFilter`] naming them, and every row
//! carries its lane. Trusted coverage additionally requires the action's before
//! state to be in the `trusted_reachable_states` view (migration 0008): a native
//! click inside a state only reachable through a synthetic click is not
//! human-realistic evidence.

use crate::codec::{conv, get, origin_label};
use crate::error::db;
use crate::pg::Pg;
use crate::repos::{key_from_row, KEY_COLS};
use crawlx_core::identity::ActionContextKey;
use crawlx_core::traffic::{TrafficOrigin, TrustLane, UnattributedReason};
use crawlx_core::{ActionId, CrawlRunId, NetworkEpochId, StoreError, Timestamp};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use sqlx::postgres::PgRow;

/// Which lanes a corpus read returns. `Both` is deliberate and explicit (`lane=all`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LaneFilter {
    /// Only `trusted_ui` rows.
    TrustedUi,
    /// Only `diagnostic` rows.
    Diagnostic,
    /// Rows of both lanes; each row still carries its lane.
    Both,
}

impl LaneFilter {
    /// The `trust_lane` labels the filter admits (bound as a text array).
    #[must_use]
    pub const fn labels(self) -> &'static [&'static str] {
        match self {
            Self::TrustedUi => &["trusted_ui"],
            Self::Diagnostic => &["diagnostic"],
            Self::Both => &["trusted_ui", "diagnostic"],
        }
    }
}

impl From<TrustLane> for LaneFilter {
    fn from(lane: TrustLane) -> Self {
        match lane {
            TrustLane::TrustedUi => Self::TrustedUi,
            TrustLane::Diagnostic => Self::Diagnostic,
        }
    }
}

impl From<Option<TrustLane>> for LaneFilter {
    /// `None` is the explicit "all lanes" choice of the API (`lane=all`).
    fn from(lane: Option<TrustLane>) -> Self {
        lane.map_or(Self::Both, Self::from)
    }
}

/// Optional equality filters on top of the lane predicate.
#[derive(Clone, Copy, Default, Debug)]
pub struct TrafficQuery<'a> {
    /// Only events of sessions with this role.
    pub role: Option<&'a str>,
    /// Only events in this network epoch.
    pub epoch: Option<NetworkEpochId>,
    /// Only events from this origin plane.
    pub origin: Option<TrafficOrigin>,
}

/// One `traffic_events` row as the corpus exposes it.
#[derive(Clone, PartialEq, Debug)]
pub struct CorpusTrafficEvent {
    /// `traffic_events.event_id` (the persisted order within a run).
    pub event_id: u64,
    /// Epoch the event was captured in; `None` only with an `unattributed_reason`
    /// (migration 0010).
    pub epoch: Option<NetworkEpochId>,
    /// Why the event has no epoch; `None` when attributed.
    pub unattributed_reason: Option<UnattributedReason>,
    /// Action owning the epoch; `None` for epochs without an action.
    pub action: Option<ActionId>,
    /// Lane of the event (always equal to the owning action's lane, migration 0008).
    pub lane: TrustLane,
    /// Role of the session that issued the request; `None` when the epoch has no session row.
    pub role: Option<String>,
    /// Plane that produced the request.
    pub origin: TrafficOrigin,
    /// HTTP method; `None` for events that have none.
    pub method: Option<String>,
    /// Redacted request URL; `None` when none was recorded.
    pub url_redacted: Option<String>,
    /// HTTP response status; `None` when no response was observed.
    pub status: Option<u16>,
    /// Request went to a host outside the target's party.
    pub third_party: bool,
    /// Request arrived after its epoch settled (`confidence = low`).
    pub late: bool,
    /// Redacted request headers; `None` when not stored.
    pub request_headers: Option<serde_json::Value>,
    /// Redacted response headers; `None` when not stored.
    pub response_headers: Option<serde_json::Value>,
    /// When the request started.
    pub occurred_at: Timestamp,
    /// The owning action started from a state in `trusted_reachable_states`.
    pub trusted_reachable: bool,
}

impl CorpusTrafficEvent {
    /// Whether the row qualifies for the authorization corpus:
    /// trusted lane, on-time, page origin, from a trusted-reachable state.
    #[must_use]
    pub fn is_corpus_eligible(&self) -> bool {
        self.lane == TrustLane::TrustedUi
            && !self.late
            && self.origin == TrafficOrigin::Page
            && self.trusted_reachable
    }
}

/// Per action-context coverage counters with the lane predicate already applied.
#[derive(Clone, PartialEq, Debug)]
pub struct CoverageRow {
    /// The context the counters belong to.
    pub key: ActionContextKey,
    /// Successful `trusted_ui` executions started from a trusted-reachable state: the only
    /// count that is coverage.
    pub trusted_exercised: u32,
    /// Successful `trusted_ui` executions from states reachable only through diagnostic
    /// actions; reported with the diagnostic lane.
    pub trusted_unreachable: u32,
    /// Successful `diagnostic` executions.
    pub diagnostic_exercised: u32,
    /// Failed executions.
    pub failures: u32,
    /// Executions the safety kernel denied.
    pub denied: u32,
    /// Executions whose outcome is unknown.
    pub unknown: u32,
    /// When the context was first seen.
    pub first_seen: Timestamp,
    /// When the context was last executed; `None` if never.
    pub last_exercised: Option<Timestamp>,
}

impl CoverageRow {
    /// Successful executions that count for `lane`.
    #[must_use]
    pub const fn exercised(&self, lane: TrustLane) -> u32 {
        match lane {
            TrustLane::TrustedUi => self.trusted_exercised,
            TrustLane::Diagnostic => self.diagnostic_exercised.saturating_add(self.trusted_unreachable),
        }
    }

    /// All successful executions regardless of lane.
    #[must_use]
    pub const fn succeeded(&self) -> u32 {
        self.trusted_exercised
            .saturating_add(self.trusted_unreachable)
            .saturating_add(self.diagnostic_exercised)
    }

    /// Exercised only by evidence that does not count (`diagnostic_only`).
    #[must_use]
    pub const fn is_diagnostic_only(&self) -> bool {
        self.trusted_exercised == 0 && self.exercised(TrustLane::Diagnostic) > 0
    }

    /// Every attempt was denied and nothing ever succeeded.
    #[must_use]
    pub const fn is_denied_only(&self) -> bool {
        self.denied > 0 && self.succeeded() == 0 && self.failures == 0 && self.unknown == 0
    }
}

/// Lane-aware reads over `traffic_events` and `action_contexts`.
#[derive(Clone, Debug)]
pub struct TrustedCorpus {
    pg: Pg,
}

fn parse_origin(s: &str) -> Result<TrafficOrigin, StoreError> {
    [
        TrafficOrigin::Page,
        TrafficOrigin::ServiceWorker,
        TrafficOrigin::WebSocket,
        TrafficOrigin::EventSource,
        TrafficOrigin::FetchPlane,
    ]
    .into_iter()
    .find(|o| origin_label(*o) == s)
    .ok_or_else(|| StoreError::Serialization(format!("unknown traffic origin {s:?}")))
}

fn parse_lane(s: &str) -> Result<TrustLane, StoreError> {
    s.parse()
        .map_err(|_| StoreError::Serialization(format!("unknown trust lane {s:?}")))
}

fn parse_reason(s: &str) -> Result<UnattributedReason, StoreError> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| StoreError::Serialization(format!("unknown unattributed reason {s:?}")))
}

fn traffic_from_row(r: &PgRow) -> Result<CorpusTrafficEvent, StoreError> {
    let status: Option<i32> = get(r, "status")?;
    Ok(CorpusTrafficEvent {
        event_id: conv(get::<i64>(r, "event_id")?, "event_id")?,
        epoch: get::<Option<uuid::Uuid>>(r, "epoch_id")?.map(NetworkEpochId),
        unattributed_reason: get::<Option<String>>(r, "unattributed_reason")?
            .map(|s| parse_reason(&s))
            .transpose()?,
        action: get::<Option<uuid::Uuid>>(r, "action_id")?.map(ActionId),
        lane: parse_lane(&get::<String>(r, "lane")?)?,
        role: get(r, "role")?,
        origin: parse_origin(&get::<String>(r, "origin")?)?,
        method: get(r, "method")?,
        url_redacted: get(r, "url_redacted")?,
        status: status.map(|s| conv(s, "status")).transpose()?,
        third_party: get(r, "third_party")?,
        late: get(r, "late")?,
        request_headers: get(r, "request_headers")?,
        response_headers: get(r, "response_headers")?,
        occurred_at: get(r, "occurred_at")?,
        trusted_reachable: get(r, "trusted_reachable")?,
    })
}

const TRAFFIC_SELECT: &str = "SELECT e.event_id, e.epoch_id, e.unattributed_reason, n.action_id, e.lane::text AS lane, s.role, e.origin, e.method, e.url_redacted, \
        e.status, e.third_party, e.late, e.request_headers, e.response_headers, e.occurred_at, \
        (a.before_state_id IS NOT NULL AND EXISTS (SELECT 1 FROM trusted_reachable_states r WHERE r.state_id = a.before_state_id)) AS trusted_reachable \
     FROM traffic_events e \
     LEFT JOIN network_epochs n ON n.epoch_id = e.epoch_id \
     LEFT JOIN actions a ON a.action_id = n.action_id \
     LEFT JOIN crawl_sessions s ON s.session_id = n.session_id \
     WHERE e.run_id = $1 AND e.lane::text = ANY($2)";

/// Count `rows` served from the corpus under `crawlx.export.trusted_rows{kind}`.
fn count_rows<T>(kind: &'static str, rows: &[T]) {
    Metrics::global()
        .counter(names::EXPORT_TRUSTED_ROWS)
        .inc_by(u64::try_from(rows.len()).unwrap_or(u64::MAX), &[("kind", kind)]);
}

impl TrustedCorpus {
    /// Corpus reads over `pg`.
    #[must_use]
    pub const fn new(pg: Pg) -> Self {
        Self { pg }
    }

    /// Traffic of `run` in the lanes `lane` admits, narrowed by `query`, in `event_id` order.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a row holds an unknown lane or origin label.
    pub async fn traffic(
        &self,
        run: CrawlRunId,
        lane: LaneFilter,
        query: &TrafficQuery<'_>,
    ) -> Result<Vec<CorpusTrafficEvent>, StoreError> {
        let _timer = self.pg.query_timer("trusted.traffic");
        let sql = format!(
            "{TRAFFIC_SELECT} AND ($3::text IS NULL OR s.role = $3) AND ($4::uuid IS NULL OR e.epoch_id = $4) \
               AND ($5::text IS NULL OR e.origin = $5) ORDER BY e.event_id"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(run.0)
            .bind(lane.labels())
            .bind(query.role)
            .bind(query.epoch.map(|e| e.0))
            .bind(query.origin.map(origin_label))
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let rows: Vec<CorpusTrafficEvent> = rows.iter().map(traffic_from_row).collect::<Result<_, _>>()?;
        count_rows("traffic", &rows);
        Ok(rows)
    }

    /// The authorization corpus of `run`: `trusted_ui`, on-time,
    /// `page` origin, from a trusted-reachable state. Every returned row satisfies
    /// [`CorpusTrafficEvent::is_corpus_eligible`].
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a row holds an unknown lane or origin label.
    pub async fn export(&self, run: CrawlRunId) -> Result<Vec<CorpusTrafficEvent>, StoreError> {
        let _timer = self.pg.query_timer("trusted.export");
        let sql = format!(
            "{TRAFFIC_SELECT} AND NOT e.late AND e.origin = 'page' \
               AND a.before_state_id IN (SELECT state_id FROM trusted_reachable_states WHERE run_id = $1) \
             ORDER BY e.event_id"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(run.0)
            .bind(LaneFilter::TrustedUi.labels())
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let rows: Vec<CorpusTrafficEvent> = rows.iter().map(traffic_from_row).collect::<Result<_, _>>()?;
        count_rows("export", &rows);
        Ok(rows)
    }

    /// Coverage rows of `run` in `context_id` order, with trusted counts restricted to
    /// trusted-reachable before states.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a counter does not fit its type.
    pub async fn coverage(&self, run: CrawlRunId) -> Result<Vec<CoverageRow>, StoreError> {
        let _timer = self.pg.query_timer("trusted.coverage");
        let sql = format!(
            "WITH reach AS (SELECT state_id FROM trusted_reachable_states WHERE run_id = $1), \
                  trusted AS (SELECT a.context_id, count(*) AS n FROM actions a JOIN reach r ON r.state_id = a.before_state_id \
                              WHERE a.run_id = $1 AND a.status = 'succeeded' AND a.lane = 'trusted_ui' GROUP BY a.context_id) \
             SELECT {KEY_COLS}, c.succeeded, c.succeeded_trusted, c.failed, c.denied, c.unknown, c.first_seen_at, c.last_exercised_at, \
                    COALESCE(t.n, 0)::int AS reachable_trusted \
             FROM action_contexts c LEFT JOIN trusted t ON t.context_id = c.context_id \
             WHERE c.run_id = $1 ORDER BY c.context_id"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(run.0)
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut coverage = Vec::with_capacity(rows.len());
        for row in &rows {
            coverage.push(coverage_from_row(&self.pg, row).await?);
        }
        count_rows("coverage", &coverage);
        Ok(coverage)
    }
}

async fn coverage_from_row(pg: &Pg, r: &PgRow) -> Result<CoverageRow, StoreError> {
    let succeeded: i32 = get(r, "succeeded")?;
    let succeeded_trusted: i32 = get(r, "succeeded_trusted")?;
    let reachable_trusted: i32 = get(r, "reachable_trusted")?;
    // A trusted-lane success is reachable or not; counters are maintained by T2 so the
    // ledger total is never below the reachable subset, but clamp anyway.
    let trusted_exercised = reachable_trusted.min(succeeded_trusted).max(0);
    Ok(CoverageRow {
        key: key_from_row(pg, r).await?,
        trusted_exercised: conv(trusted_exercised, "trusted_exercised")?,
        trusted_unreachable: conv(
            (succeeded_trusted - trusted_exercised).max(0),
            "trusted_unreachable",
        )?,
        diagnostic_exercised: conv((succeeded - succeeded_trusted).max(0), "diagnostic_exercised")?,
        failures: conv(get::<i32>(r, "failed")?, "failed")?,
        denied: conv(get::<i32>(r, "denied")?, "denied")?,
        unknown: conv(get::<i32>(r, "unknown")?, "unknown")?,
        first_seen: get(r, "first_seen_at")?,
        last_exercised: get(r, "last_exercised_at")?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::Utc;
    use crawlx_core::hash::Digest;
    use crawlx_core::identity::{ActionKind, ElementIdentityHash, InputClass, ResourceContext};
    use crawlx_core::url::RouteTemplate;
    use crawlx_core::{PrincipalId, StateClusterId};

    fn row(trusted: u32, unreachable: u32, diagnostic: u32, denied: u32) -> CoverageRow {
        CoverageRow {
            key: ActionContextKey {
                principal: PrincipalId("p".to_owned()),
                route_template: RouteTemplate("/".to_owned()),
                element: ElementIdentityHash(Digest::of("crawlx/test/element", b"e")),
                action_kind: ActionKind::Click,
                input_class: InputClass::none(),
                resource_context: ResourceContext::None,
                state_cluster: StateClusterId::new(),
            },
            trusted_exercised: trusted,
            trusted_unreachable: unreachable,
            diagnostic_exercised: diagnostic,
            failures: 0,
            denied,
            unknown: 0,
            first_seen: Utc::now(),
            last_exercised: None,
        }
    }

    #[test]
    fn lane_filter_labels_always_name_lanes() {
        assert_eq!(LaneFilter::from(TrustLane::TrustedUi).labels(), ["trusted_ui"]);
        assert_eq!(LaneFilter::from(None).labels(), ["trusted_ui", "diagnostic"]);
        assert_eq!(LaneFilter::Diagnostic.labels(), ["diagnostic"]);
    }

    #[test]
    fn unreachable_trusted_successes_count_as_diagnostic() {
        let r = row(0, 2, 1, 0);
        assert_eq!(r.exercised(TrustLane::TrustedUi), 0);
        assert_eq!(r.exercised(TrustLane::Diagnostic), 3);
        assert!(r.is_diagnostic_only());
        assert!(!row(1, 0, 5, 0).is_diagnostic_only());
        assert!(row(0, 0, 0, 2).is_denied_only());
        assert!(!row(0, 1, 0, 2).is_denied_only());
        let mut mixed = row(0, 0, 0, 2);
        mixed.failures = 1;
        assert!(
            !mixed.is_denied_only(),
            "an executed failure is not a kernel denial"
        );
        mixed.failures = 0;
        mixed.unknown = 1;
        assert!(
            !mixed.is_denied_only(),
            "an unknown effect cannot be labelled denied"
        );
    }

    #[test]
    fn origin_labels_round_trip() {
        for o in [
            TrafficOrigin::Page,
            TrafficOrigin::ServiceWorker,
            TrafficOrigin::WebSocket,
            TrafficOrigin::EventSource,
            TrafficOrigin::FetchPlane,
        ] {
            assert_eq!(parse_origin(origin_label(o)).unwrap(), o);
        }
        assert!(parse_origin("sse").is_err());
    }
}
