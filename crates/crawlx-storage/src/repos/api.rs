//! SQL behind the API's own persistence: `api_keys`,
//! `idempotency_keys`, `approvals`, `transitions` (joined with their action), replay
//! tagging on `crawl_runs`, `authorization_records` and the `webhook_deliveries` outbox.
//!
//! [`PgApiRepo`] is the only place these tables are queried; `crawlx-api` maps the row
//! types here onto its own wire types. Enum columns are bound as text and read back as
//! `col::text`.

use crate::codec::{conv, get, parse_label};
use crate::error::{db, not_found};
use crate::Pg;
use crawlx_core::counters::ActionStatus;
use crawlx_core::hash::Digest;
use crawlx_core::traffic::TrustLane;
use crawlx_core::{
    ActionId, ApprovalId, CrawlRunId, NetworkEpochId, SessionId, StateId, StoreError, TenantId, Timestamp,
    TransitionId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::PgRow;
use uuid::Uuid;

/// Idempotency keys live this long after they are claimed.
const IDEMPOTENCY_TTL_HOURS: i64 = 24;

fn serialization(msg: impl Into<String>) -> StoreError {
    StoreError::Serialization(msg.into())
}

/// One `api_keys` row. `scopes` are the stored scope labels, unparsed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ApiKeyRow {
    /// `api_keys.key_id`, the stable identifier of the key.
    pub key_id: Uuid,
    /// Tenant that owns the key.
    pub tenant: TenantId,
    /// First characters of the secret part; unique.
    pub prefix: String,
    /// BLAKE3-256 digest of the full key string.
    pub hash: [u8; 32],
    /// Scope labels as stored in `api_keys.scopes`.
    pub scopes: Vec<String>,
    /// Instant after which the key is rejected; `None` = never expires.
    pub expires_at: Option<Timestamp>,
    /// `true` once `api_keys.revoked_at` is set.
    pub revoked: bool,
}

/// The response stored against a completed idempotency key.
#[derive(Clone, PartialEq, Debug)]
pub struct IdemResponse {
    /// HTTP status code of the original response.
    pub status: u16,
    /// JSON body of the original response.
    pub body: Value,
    /// Run the original request created, when it created one.
    pub run_id: Option<CrawlRunId>,
}

/// Outcome of [`PgApiRepo::idem_begin`].
#[derive(Clone, PartialEq, Debug)]
pub enum IdemClaim {
    /// First use: the row was inserted in `in_progress`.
    Started,
    /// Same key, same request hash, finished: the stored response.
    Done(IdemResponse),
    /// Same key, same request, still `in_progress`.
    InProgress,
    /// Same key with a different request hash.
    Mismatch,
}

/// `approvals.decision`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Awaiting a decision; becomes effectively [`Self::Expired`] once `expires_at` passes.
    Pending,
    /// A reviewer approved the action; the worker may run it once.
    Approved,
    /// A reviewer denied the action; it never runs.
    Denied,
    /// The decision window closed with no decision.
    Expired,
}

impl ApprovalDecision {
    /// The wire and column form of the decision (`approvals.decision`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Parse the wire form; unknown values are `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// An `approvals` row.
#[derive(Clone, PartialEq, Debug)]
pub struct ApprovalRecord {
    /// `approvals.approval_id`.
    pub id: ApprovalId,
    /// Run the held action belongs to.
    pub run: CrawlRunId,
    /// Action held pending this approval.
    pub action: ActionId,
    /// Risk class the safety kernel assigned to the action (for example `navigation_reveal`).
    pub risk_class: String,
    /// Redacted reviewer summary (`role`, `route_template`, `action_kind`, ...).
    pub summary: Value,
    /// Stored decision; `pending` rows past `expires_at` are reported `expired` by the routes.
    pub decision: ApprovalDecision,
    /// When the safety kernel requested the approval.
    pub requested_at: Timestamp,
    /// Instant after which an undecided approval counts as expired.
    pub expires_at: Timestamp,
    /// Key that decided the approval; `None` while pending or expired undecided.
    pub decided_by: Option<Uuid>,
    /// When the decision was applied; `None` while pending.
    pub decided_at: Option<Timestamp>,
    /// Free-text reviewer reason supplied with the decision; `None` when none was given.
    pub reason: Option<String>,
    /// Set by the worker when the intent journal consumed the approval (single use).
    pub consumed_at: Option<Timestamp>,
}

impl ApprovalRecord {
    /// The decision as clients see it at `now`.
    #[must_use]
    pub fn effective(&self, now: Timestamp) -> ApprovalDecision {
        if self.decision == ApprovalDecision::Pending && self.expires_at <= now {
            ApprovalDecision::Expired
        } else {
            self.decision
        }
    }
}

/// Result of [`PgApiRepo::approval_decide`].
#[derive(Clone, PartialEq, Debug)]
pub enum DecideOutcome {
    /// The decision was applied now.
    Applied(ApprovalRecord),
    /// The same decision had already been applied (idempotent repeat).
    Unchanged(ApprovalRecord),
    /// Decided the other way, expired or consumed.
    NotPending(ApprovalRecord),
    /// No approval with that id exists in the run.
    NotFound,
}

/// Action summary embedded in a transition.
#[derive(Clone, PartialEq, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ActionSummary {
    /// Action id.
    pub id: ActionId,
    /// Position of the action in the run's action sequence (starts at 1).
    pub seq: u64,
    /// Action kind label (for example `navigate`, `click`).
    pub kind: String,
    /// Terminal or current status of the action.
    pub status: ActionStatus,
    /// Trust lane the action ran in; `None` when the action was never dispatched to a lane.
    pub lane: Option<TrustLane>,
    /// Fidelity tier label the action ran at; `None` when not yet dispatched.
    pub fidelity: Option<String>,
    /// Name of the strategy that proposed the action.
    pub strategy: String,
    /// Version of that strategy at proposal time.
    pub strategy_version: u32,
    /// Opaque identifier of the action context, a lowercase hex digest.
    pub context_id: String,
    /// Risk class from the safety decision; `None` when no safety decision is recorded.
    pub risk_class: Option<String>,
    /// Safety verdict (for example `allow`); `None` when no safety decision is recorded.
    pub safety_verdict: Option<String>,
}

/// `transitions` row joined with its action.
#[derive(Clone, PartialEq, Debug)]
pub struct TransitionRecord {
    /// `transitions.transition_id`; ordering by it is the listing order.
    pub id: TransitionId,
    /// Crawl session the transition happened in.
    pub session: SessionId,
    /// Role (principal) the session acted as.
    pub role: String,
    /// State observed before the action ran.
    pub before: StateId,
    /// State observed after the action settled; `None` when no new state was captured.
    pub after: Option<StateId>,
    /// Network epoch that captured the action's traffic; `None` when none was opened.
    pub network_epoch: Option<NetworkEpochId>,
    /// Trust lane the transition ran in.
    pub lane: TrustLane,
    /// Settle report JSON (what the page did after the action); `None` when unavailable.
    pub settle: Option<Value>,
    /// The action that caused the transition.
    pub action: ActionSummary,
    /// When the transition was recorded.
    pub created_at: Timestamp,
}

/// Optional equality filters for listing transitions; unset fields match everything.
#[derive(Clone, Default, Debug)]
pub struct TransitionFilter {
    /// Only transitions of this session.
    pub session: Option<SessionId>,
    /// Only transitions of this role.
    pub role: Option<String>,
    /// Only transitions in this trust lane.
    pub lane: Option<TrustLane>,
    /// Only transitions whose action ended with this status.
    pub status: Option<ActionStatus>,
    /// Only transitions that started from this state.
    pub from_state: Option<StateId>,
    /// Only transitions that ended in this state.
    pub to_state: Option<StateId>,
}

/// `webhook_deliveries.status`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Queued; due at `next_attempt_at`.
    Pending,
    /// The receiver acknowledged with a 2xx status.
    Delivered,
    /// Retries exhausted or the failure is permanent; never retried.
    Dead,
}

impl DeliveryStatus {
    /// The wire and column form of the status (`webhook_deliveries.status`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Dead => "dead",
        }
    }

    /// Parse the wire form; unknown values are `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "delivered" => Some(Self::Delivered),
            "dead" => Some(Self::Dead),
            _ => None,
        }
    }
}

/// One outbox row.
#[derive(Clone, PartialEq, Debug)]
pub struct WebhookDelivery {
    /// `webhook_deliveries.delivery_id`.
    pub id: Uuid,
    /// Run the event belongs to.
    pub run: CrawlRunId,
    /// Sequence number of the run event being delivered; `(run, event_seq, url)` is unique.
    pub event_seq: u64,
    /// Event type label sent to the receiver.
    pub event_type: String,
    /// Receiver URL.
    pub url: String,
    /// Current delivery state.
    pub status: DeliveryStatus,
    /// Attempts made so far; each recorded result increments it.
    pub attempts: u16,
    /// Earliest instant the next attempt may start; claiming defers it by the lease.
    pub next_attempt_at: Timestamp,
    /// When the receiver acknowledged; `None` until delivered.
    pub delivered_at: Option<Timestamp>,
    /// HTTP status of the latest attempt; `None` before the first attempt or when none was received.
    pub last_status: Option<u16>,
    /// Error text of the latest failed attempt; `None` after a success or before any attempt.
    pub last_error: Option<String>,
}

/// How a delivery attempt ended.
#[derive(Clone, PartialEq, Debug)]
pub enum DeliveryResult {
    /// The receiver acknowledged.
    Delivered {
        /// HTTP status of the acknowledging response.
        status: u16,
        /// When the acknowledgement arrived.
        at: Timestamp,
    },
    /// The attempt failed; try again later.
    Retry {
        /// HTTP status when a response arrived; `None` for transport errors.
        status: Option<u16>,
        /// Short error description.
        error: String,
        /// Earliest instant of the next attempt.
        next_attempt_at: Timestamp,
    },
    /// The attempt failed permanently; stop retrying.
    Dead {
        /// HTTP status when a response arrived; `None` for transport errors.
        status: Option<u16>,
        /// Short error description.
        error: String,
    },
}

const APPROVAL_COLS: &str =
    "approval_id, run_id, action_id, risk_class::text AS risk_class, summary, decision, \
     requested_at, expires_at, decided_by, decided_at, reason, consumed_at";

fn approval_from_row(r: &PgRow) -> Result<ApprovalRecord, StoreError> {
    let decision: String = get(r, "decision")?;
    Ok(ApprovalRecord {
        id: ApprovalId(get(r, "approval_id")?),
        run: CrawlRunId(get(r, "run_id")?),
        action: ActionId(get(r, "action_id")?),
        risk_class: get(r, "risk_class")?,
        summary: get(r, "summary")?,
        decision: ApprovalDecision::parse(&decision)
            .ok_or_else(|| serialization(format!("unknown approval decision {decision:?}")))?,
        requested_at: get(r, "requested_at")?,
        expires_at: get(r, "expires_at")?,
        decided_by: get(r, "decided_by")?,
        decided_at: get(r, "decided_at")?,
        reason: get(r, "reason")?,
        consumed_at: get(r, "consumed_at")?,
    })
}

const WEBHOOK_COLS: &str =
    "delivery_id, run_id, event_seq, event_type, url, status, attempts, next_attempt_at, delivered_at, last_status, last_error";

async fn delivery_from_row(pg: &Pg, r: &PgRow) -> Result<WebhookDelivery, StoreError> {
    let run = CrawlRunId(get(r, "run_id")?);
    let id: Uuid = get(r, "delivery_id")?;
    let (tenant, zdr) = pg.privacy_scope(run).await?;
    let url = if zdr {
        pg.ephemeral_get(tenant, run, i64::MIN + 2, &format!("webhook_{id}"))
            .await?
    } else {
        get(r, "url")?
    };
    let status: String = get(r, "status")?;
    let last_status: Option<i32> = get(r, "last_status")?;
    Ok(WebhookDelivery {
        id,
        run,
        event_seq: conv(get::<i64>(r, "event_seq")?, "event_seq")?,
        event_type: get(r, "event_type")?,
        url,
        status: DeliveryStatus::parse(&status)
            .ok_or_else(|| serialization(format!("unknown delivery status {status:?}")))?,
        attempts: conv(get::<i16>(r, "attempts")?, "attempts")?,
        next_attempt_at: get(r, "next_attempt_at")?,
        delivered_at: get(r, "delivered_at")?,
        last_status: last_status.map(|s| conv(s, "last_status")).transpose()?,
        last_error: get(r, "last_error")?,
    })
}

fn transition_from_row(r: &PgRow) -> Result<TransitionRecord, StoreError> {
    Ok(TransitionRecord {
        id: TransitionId(get(r, "transition_id")?),
        session: SessionId(get(r, "session_id")?),
        role: get(r, "role")?,
        before: StateId(get(r, "before_state_id")?),
        after: get::<Option<Uuid>>(r, "after_state_id")?.map(StateId),
        network_epoch: get::<Option<Uuid>>(r, "network_epoch_id")?.map(NetworkEpochId),
        lane: parse_label(&get::<String>(r, "lane")?)?,
        settle: get(r, "settle_report")?,
        action: ActionSummary {
            id: ActionId(get(r, "action_id")?),
            seq: conv(get::<i64>(r, "seq")?, "seq")?,
            kind: get(r, "kind")?,
            status: parse_label(&get::<String>(r, "status")?)?,
            lane: Some(parse_label(&get::<String>(r, "action_lane")?)?),
            fidelity: get(r, "fidelity")?,
            strategy: get(r, "strategy")?,
            strategy_version: conv(get::<i32>(r, "strategy_version")?, "strategy_version")?,
            context_id: get(r, "context_id")?,
            risk_class: get(r, "risk_class")?,
            safety_verdict: get(r, "verdict")?,
        },
        created_at: get(r, "created_at")?,
    })
}

/// Repository for the API-owned tables over a [`Pg`] pool.
#[derive(Clone, Debug)]
pub struct PgApiRepo {
    pub(super) pg: Pg,
}

impl PgApiRepo {
    /// API-table access over `pg`.
    #[must_use]
    pub const fn new(pg: Pg) -> Self {
        Self { pg }
    }

    // ---- API keys -------------------------------------------------------

    /// The key whose prefix is `prefix`; `None` when absent.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or the stored hash is not 32 bytes.
    pub async fn key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKeyRow>, StoreError> {
        let _timer = self.pg.query_timer("api.key_by_prefix");
        let row = sqlx::query(
            "SELECT key_id, tenant_id, prefix, key_hash, scopes, expires_at, revoked_at FROM crawlx_authenticate_key($1)",
        )
        .bind(prefix)
        .fetch_optional(self.pg.pool.authentication())
        .await
        .map_err(db)?;
        let Some(r) = row else { return Ok(None) };
        let hash: Vec<u8> = get(&r, "key_hash")?;
        let hash: [u8; 32] = hash.try_into().map_err(|h: Vec<u8>| {
            serialization(format!("api key hash has {} bytes, expected 32", h.len()))
        })?;
        let revoked_at: Option<Timestamp> = get(&r, "revoked_at")?;
        Ok(Some(ApiKeyRow {
            key_id: get(&r, "key_id")?,
            tenant: TenantId(get(&r, "tenant_id")?),
            prefix: get(&r, "prefix")?,
            hash,
            scopes: get(&r, "scopes")?,
            expires_at: get(&r, "expires_at")?,
            revoked: revoked_at.is_some(),
        }))
    }

    /// Insert `key` after ensuring its tenant exists (named `tenant_name`). Idempotent on
    /// `prefix`: an existing row wins.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the tenant upsert or the insert fails.
    pub async fn key_insert(&self, key: &ApiKeyRow, tenant_name: &str) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.key_insert");
        self.pg.ensure_tenant(key.tenant, tenant_name).await?;
        sqlx::query(
            "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes, expires_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN now() END) ON CONFLICT (prefix) DO NOTHING",
        )
        .bind(key.key_id)
        .bind(key.tenant.0)
        .bind(&key.prefix)
        .bind(key.hash.as_slice())
        .bind(&key.scopes)
        .bind(key.expires_at)
        .bind(key.revoked)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Set `api_keys.last_used_at` of `key_id` to `at`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the update fails.
    pub async fn key_touch(&self, key_id: Uuid, at: Timestamp) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.key_touch");
        sqlx::query("UPDATE api_keys SET last_used_at = $2 WHERE key_id = $1")
            .bind(key_id)
            .bind(at)
            .execute(&self.pg.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    // ---- idempotency ------------------------------------------------------

    /// Claim `key` for `tenant` with `request_hash`; expired rows are replaced first.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] if a concurrent release or expiry removes the row
    /// three times in a row, [`StoreError::Serialization`] for an unknown `state` label and
    /// other [`StoreError`]s if a statement fails.
    pub async fn idem_begin(
        &self,
        tenant: TenantId,
        key: &str,
        request_hash: Digest,
        now: Timestamp,
    ) -> Result<IdemClaim, StoreError> {
        let _timer = self.pg.query_timer("api.idem_begin");
        let pool = &self.pg.pool;
        // A concurrent release/expiry can remove the row between the INSERT and the SELECT; retry.
        for _ in 0..3 {
            sqlx::query(
                "DELETE FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2 AND expires_at <= $3",
            )
            .bind(tenant.0)
            .bind(key)
            .bind(now)
            .execute(pool)
            .await
            .map_err(db)?;
            let inserted = sqlx::query(
                "INSERT INTO idempotency_keys (tenant_id, idem_key, request_hash, state, expires_at) \
                 VALUES ($1, $2, $3, 'in_progress', $4) ON CONFLICT (tenant_id, idem_key) DO NOTHING",
            )
            .bind(tenant.0)
            .bind(key)
            .bind(request_hash.0.as_slice())
            .bind(now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS))
            .execute(pool)
            .await
            .map_err(db)?
            .rows_affected();
            if inserted == 1 {
                return Ok(IdemClaim::Started);
            }
            let row = sqlx::query(
                "SELECT request_hash, state, response_status, response_body, run_id FROM idempotency_keys \
                 WHERE tenant_id = $1 AND idem_key = $2",
            )
            .bind(tenant.0)
            .bind(key)
            .fetch_optional(pool)
            .await
            .map_err(db)?;
            let Some(r) = row else { continue };
            let stored_hash: Vec<u8> = get(&r, "request_hash")?;
            if stored_hash.as_slice() != request_hash.0.as_slice() {
                return Ok(IdemClaim::Mismatch);
            }
            let state: String = get(&r, "state")?;
            return match state.as_str() {
                "in_progress" => Ok(IdemClaim::InProgress),
                "done" => {
                    let status: Option<i32> = get(&r, "response_status")?;
                    let status = status
                        .ok_or_else(|| serialization("completed idempotency key without response_status"))?;
                    let body: Option<Value> = get(&r, "response_body")?;
                    let run_id: Option<Uuid> = get(&r, "run_id")?;
                    Ok(IdemClaim::Done(IdemResponse {
                        status: conv(status, "response_status")?,
                        body: body.unwrap_or(Value::Null),
                        run_id: run_id.map(CrawlRunId),
                    }))
                }
                other => Err(serialization(format!("unknown idempotency state {other:?}"))),
            };
        }
        Err(StoreError::Conflict(format!(
            "idempotency key {key:?} changed concurrently"
        )))
    }

    /// Mark `key` done with `response`. A key that no longer exists (released or expired
    /// meanwhile) is a no-op: the request already ran and must not fail afterwards.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the update fails.
    pub async fn idem_complete(
        &self,
        tenant: TenantId,
        key: &str,
        response: &IdemResponse,
    ) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.idem_complete");
        sqlx::query(
            "UPDATE idempotency_keys SET state = 'done', response_status = $3, response_body = $4, run_id = $5 \
             WHERE tenant_id = $1 AND idem_key = $2",
        )
        .bind(tenant.0)
        .bind(key)
        .bind(i32::from(response.status))
        .bind(&response.body)
        .bind(response.run_id.map(|r| r.0))
        .execute(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Drop the `in_progress` claim on `key`; completed keys are kept.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the delete fails.
    pub async fn idem_release(&self, tenant: TenantId, key: &str) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.idem_release");
        sqlx::query(
            "DELETE FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2 AND state = 'in_progress'",
        )
        .bind(tenant.0)
        .bind(key)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Record `run` as the run the `in_progress` claim on `key` is about to create, so a repeat
    /// that arrives before the claim completes can name it ([`Self::idem_run`]). A key that is
    /// no longer `in_progress` is left as it is.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the update fails.
    pub async fn idem_link_run(
        &self,
        tenant: TenantId,
        key: &str,
        run: CrawlRunId,
    ) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.idem_link_run");
        sqlx::query(
            "UPDATE idempotency_keys SET run_id = $3 WHERE tenant_id = $1 AND idem_key = $2 AND state = 'in_progress'",
        )
        .bind(tenant.0)
        .bind(key)
        .bind(run.0)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The run linked to `key`: the one an `in_progress` claim announced
    /// ([`Self::idem_link_run`]) or the one a completed claim created. `None` when the key is
    /// unknown or carries no run.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn idem_run(&self, tenant: TenantId, key: &str) -> Result<Option<CrawlRunId>, StoreError> {
        let _timer = self.pg.query_timer("api.idem_run");
        let run: Option<Option<Uuid>> =
            sqlx::query_scalar("SELECT run_id FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2")
                .bind(tenant.0)
                .bind(key)
                .fetch_optional(&self.pg.pool)
                .await
                .map_err(db)?;
        Ok(run.flatten().map(CrawlRunId))
    }

    // ---- approvals --------------------------------------------------------

    /// Every approval of `run`, ordered by approval id.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or a row holds an unknown decision label.
    pub async fn approvals_list(&self, run: CrawlRunId) -> Result<Vec<ApprovalRecord>, StoreError> {
        let _timer = self.pg.query_timer("api.approvals_list");
        let sql = format!("SELECT {APPROVAL_COLS} FROM approvals WHERE run_id = $1 ORDER BY approval_id");
        let rows = sqlx::query(&sql)
            .bind(run.0)
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        rows.iter().map(approval_from_row).collect()
    }

    /// One approval of `run`; `None` when the id is unknown or belongs to another run.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or the row holds an unknown decision label.
    pub async fn approval_get(
        &self,
        run: CrawlRunId,
        id: ApprovalId,
    ) -> Result<Option<ApprovalRecord>, StoreError> {
        let _timer = self.pg.query_timer("api.approval_get");
        let sql = format!("SELECT {APPROVAL_COLS} FROM approvals WHERE run_id = $1 AND approval_id = $2");
        let row = sqlx::query(&sql)
            .bind(run.0)
            .bind(id.0)
            .fetch_optional(&self.pg.pool)
            .await
            .map_err(db)?;
        row.as_ref().map(approval_from_row).transpose()
    }

    /// Apply `Approved` or `Denied` to a pending, unexpired, unconsumed approval in one
    /// transaction; approving releases the held action (`actions.hold = 'none'`), denying
    /// marks it `denied`.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] when `decision` is `Pending` or `Expired`, and other
    /// [`StoreError`]s if a statement fails.
    pub async fn approval_decide(
        &self,
        run: CrawlRunId,
        id: ApprovalId,
        decision: ApprovalDecision,
        decided_by: Uuid,
        reason: Option<&str>,
        now: Timestamp,
    ) -> Result<DecideOutcome, StoreError> {
        let _timer = self.pg.query_timer("api.approval_decide");
        let hold = match decision {
            ApprovalDecision::Approved => "none",
            ApprovalDecision::Denied => "denied",
            ApprovalDecision::Pending | ApprovalDecision::Expired => {
                return Err(StoreError::Conflict(format!(
                    "an approval cannot be decided as {}",
                    decision.as_str()
                )))
            }
        };
        let mut tx = self.pg.pool.begin().await.map_err(db)?;
        let sql = format!(
            "SELECT {APPROVAL_COLS} FROM approvals WHERE run_id = $1 AND approval_id = $2 FOR UPDATE"
        );
        let row = sqlx::query(&sql)
            .bind(run.0)
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let Some(row) = row else {
            return Ok(DecideOutcome::NotFound);
        };
        let current = approval_from_row(&row)?;
        if current.decision == decision {
            return Ok(DecideOutcome::Unchanged(current));
        }
        if current.decision != ApprovalDecision::Pending
            || current.expires_at <= now
            || current.consumed_at.is_some()
        {
            return Ok(DecideOutcome::NotPending(current));
        }
        let sql = format!(
            "UPDATE approvals SET decision = $2, decided_by = $3, decided_at = $4, reason = $5 \
             WHERE approval_id = $1 RETURNING {APPROVAL_COLS}"
        );
        let updated = sqlx::query(&sql)
            .bind(id.0)
            .bind(decision.as_str())
            .bind(decided_by)
            .bind(now)
            .bind(reason)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let updated = approval_from_row(&updated)?;
        sqlx::query("UPDATE actions SET hold = $2 WHERE action_id = $1")
            .bind(updated.action.0)
            .bind(hold)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(DecideOutcome::Applied(updated))
    }

    // ---- transitions --------------------------------------------------------

    /// Transitions of `run` matching `filter`, joined with their action, session role,
    /// context hash and safety decision, ordered by transition id.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or a row holds an unknown label or an
    /// out-of-range counter.
    pub async fn transitions_list(
        &self,
        run: CrawlRunId,
        filter: &TransitionFilter,
    ) -> Result<Vec<TransitionRecord>, StoreError> {
        let _timer = self.pg.query_timer("api.transitions_list");
        let rows = sqlx::query(
            "SELECT t.transition_id, t.session_id, s.role, t.before_state_id, t.after_state_id, t.network_epoch_id, \
                    t.lane::text AS lane, t.settle_report, t.created_at, \
                    a.action_id, a.seq, a.action_kind::text AS kind, a.status::text AS status, a.lane::text AS action_lane, \
                    a.fidelity::text AS fidelity, a.strategy, a.strategy_version, \
                    encode(c.context_hash, 'hex') AS context_id, sd.risk_class::text AS risk_class, sd.verdict \
             FROM transitions t \
             JOIN actions a ON a.action_id = t.action_id \
             JOIN crawl_sessions s ON s.session_id = t.session_id \
             JOIN action_contexts c ON c.context_id = a.context_id \
             LEFT JOIN safety_decisions sd ON sd.decision_id = a.safety_decision_id \
             WHERE t.run_id = $1 \
               AND ($2::uuid IS NULL OR t.session_id = $2) \
               AND ($3::text IS NULL OR s.role = $3) \
               AND ($4::text IS NULL OR t.lane::text = $4) \
               AND ($5::text IS NULL OR a.status::text = $5) \
               AND ($6::uuid IS NULL OR t.before_state_id = $6) \
               AND ($7::uuid IS NULL OR t.after_state_id = $7) \
             ORDER BY t.transition_id",
        )
        .bind(run.0)
        .bind(filter.session.map(|s| s.0))
        .bind(filter.role.as_deref())
        .bind(filter.lane.map(TrustLane::as_str))
        .bind(filter.status.map(ActionStatus::as_str))
        .bind(filter.from_state.map(|s| s.0))
        .bind(filter.to_state.map(|s| s.0))
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        rows.iter().map(transition_from_row).collect()
    }

    // ---- runs -------------------------------------------------------------

    /// Number of runs of `tenant` in `queued|running|pausing|paused`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn active_run_count(&self, tenant: TenantId) -> Result<u64, StoreError> {
        let _timer = self.pg.query_timer("api.active_run_count");
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crawl_runs WHERE tenant_id = $1 AND status::text IN ('queued','running','pausing','paused')",
        )
        .bind(tenant.0)
        .fetch_one(&self.pg.pool)
        .await
        .map_err(db)?;
        conv(n, "count")
    }

    /// Ids of the runs of `tenant` in `queued|running|pausing|paused`, oldest first.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn active_runs(&self, tenant: TenantId) -> Result<Vec<CrawlRunId>, StoreError> {
        let _timer = self.pg.query_timer("api.active_runs");
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT run_id FROM crawl_runs WHERE tenant_id = $1 AND status::text IN ('queued','running','pausing','paused') ORDER BY created_at, run_id",
        )
        .bind(tenant.0)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(ids.into_iter().map(CrawlRunId).collect())
    }

    /// Mark `run` as `run_kind = 'shadow'` (a mirrored crawl).
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when `run` does not exist and other [`StoreError`]s
    /// if the update fails.
    pub async fn shadow_tag(&self, run: CrawlRunId) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.shadow_tag");
        let n = sqlx::query("UPDATE crawl_runs SET run_kind = 'shadow' WHERE run_id = $1")
            .bind(run.0)
            .execute(&self.pg.pool)
            .await
            .map_err(db)?
            .rows_affected();
        if n == 0 {
            return Err(not_found("crawl_run", run));
        }
        Ok(())
    }

    // ---- webhook outbox -----------------------------------------------------

    /// Runs whose configuration carries a webhook URL (`config.output.webhook.url`), in
    /// run-id order.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn webhook_runs(&self) -> Result<Vec<CrawlRunId>, StoreError> {
        let _timer = self.pg.query_timer("api.webhook_runs");
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT run_id FROM crawl_runs WHERE config->'output'->'webhook'->>'url' IS NOT NULL \
             OR (retention_mode = 'zdr' AND config->>'webhookConfigured' = 'true') ORDER BY run_id",
        )
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(ids.into_iter().map(CrawlRunId).collect())
    }

    /// Highest `event_seq` queued for `run`; `0` when none.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn webhook_cursor(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let _timer = self.pg.query_timer("api.webhook_cursor");
        let n: i64 = sqlx::query_scalar(
            "SELECT COALESCE(max(event_seq), 0) FROM webhook_deliveries WHERE run_id = $1",
        )
        .bind(run.0)
        .fetch_one(&self.pg.pool)
        .await
        .map_err(db)?;
        conv(n, "event_seq")
    }

    /// Queue `d`; `false` when `(run, event_seq, url)` is already queued.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] when `event_seq` or `attempts` do not fit their
    /// columns and other [`StoreError`]s if the transaction fails.
    pub async fn webhook_enqueue(&self, d: &WebhookDelivery) -> Result<bool, StoreError> {
        let _timer = self.pg.query_timer("api.webhook_enqueue");
        let event_seq: i64 = conv(d.event_seq, "event_seq")?;
        let attempts: i16 = conv(d.attempts, "attempts")?;
        let (tenant, zdr) = self.pg.privacy_scope(d.run).await?;
        let durable_url = if zdr {
            self.pg
                .ephemeral_put(tenant, d.run, i64::MIN + 2, &format!("webhook_{}", d.id), &d.url)
                .await?;
            Digest::of("crawlx/zdr-webhook-url/v1", d.url.as_bytes()).to_hex()
        } else {
            d.url.clone()
        };
        let mut tx = self.pg.pool.begin().await.map_err(db)?;
        // `webhook_deliveries` has no unique key over (run, event_seq, url); serialize racing enqueuers.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("webhook:{}:{}:{}", d.run.0, event_seq, durable_url))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let n = sqlx::query(
            "INSERT INTO webhook_deliveries (delivery_id, run_id, event_seq, event_type, url, status, attempts, \
               next_attempt_at, delivered_at, last_status, last_error) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 \
             WHERE NOT EXISTS (SELECT 1 FROM webhook_deliveries WHERE run_id = $2 AND event_seq = $3 AND url = $5)",
        )
        .bind(d.id)
        .bind(d.run.0)
        .bind(event_seq)
        .bind(&d.event_type)
        .bind(&durable_url)
        .bind(d.status.as_str())
        .bind(attempts)
        .bind(d.next_attempt_at)
        .bind(d.delivered_at)
        .bind(d.last_status.map(i32::from))
        .bind(d.last_error.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
        tx.commit().await.map_err(db)?;
        Ok(n == 1)
    }

    /// Claim up to `limit` pending deliveries due at `now` (`SKIP LOCKED`), deferring each
    /// by `lease_secs`; returned in `(due_at, delivery_id)` order.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the statement fails or a row holds an unknown status label
    /// or an out-of-range counter.
    pub async fn webhook_claim_due(
        &self,
        now: Timestamp,
        limit: u32,
        lease_secs: u32,
    ) -> Result<Vec<WebhookDelivery>, StoreError> {
        let _timer = self.pg.query_timer("api.webhook_claim_due");
        let sql = format!(
            "WITH due AS (SELECT delivery_id, next_attempt_at AS due_at FROM webhook_deliveries \
                          WHERE status = 'pending' AND next_attempt_at <= $1 \
                          ORDER BY next_attempt_at, delivery_id LIMIT $2 FOR UPDATE SKIP LOCKED) \
             UPDATE webhook_deliveries w SET next_attempt_at = $1 + make_interval(secs => $3) \
             FROM due WHERE w.delivery_id = due.delivery_id \
             RETURNING {}, due.due_at",
            WEBHOOK_COLS
                .split(", ")
                .map(|c| format!("w.{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let rows = sqlx::query(&sql)
            .bind(now)
            .bind(i64::from(limit))
            .bind(f64::from(lease_secs))
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            match delivery_from_row(&self.pg, row).await {
                Ok(delivery) => out.push((get::<Timestamp>(row, "due_at")?, delivery)),
                Err(StoreError::RetentionDenied(_)) => {
                    // Expired volatile content cannot be delivered. Do not let one expired
                    // ZDR receiver block unrelated tenants' durable deliveries.
                    sqlx::query("UPDATE webhook_deliveries SET status = 'dead', last_error = 'zdr delivery window expired' \
                        WHERE delivery_id = $1 AND status = 'pending'")
                        .bind(get::<Uuid>(row, "delivery_id")?)
                        .execute(&self.pg.pool).await.map_err(db)?;
                }
                Err(error) => return Err(error),
            }
        }
        out.sort_by_key(|(due, d)| (*due, d.id));
        Ok(out.into_iter().map(|(_, d)| d).collect())
    }

    /// Apply the outcome of one attempt to delivery `id`; every outcome increments `attempts`.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when `id` is unknown and other [`StoreError`]s if the
    /// update fails.
    pub async fn webhook_record(&self, id: Uuid, result: &DeliveryResult) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.webhook_record");
        let q = match result {
            DeliveryResult::Delivered { status, at } => sqlx::query(
                "UPDATE webhook_deliveries SET status = 'delivered', attempts = attempts + 1, delivered_at = $2, \
                   last_status = $3, last_error = NULL WHERE delivery_id = $1",
            )
            .bind(id)
            .bind(*at)
            .bind(i32::from(*status)),
            DeliveryResult::Retry { status, error, next_attempt_at } => sqlx::query(
                "UPDATE webhook_deliveries SET status = 'pending', attempts = attempts + 1, next_attempt_at = $2, \
                   last_status = $3, last_error = $4 WHERE delivery_id = $1",
            )
            .bind(id)
            .bind(*next_attempt_at)
            .bind(status.map(i32::from))
            .bind(error),
            DeliveryResult::Dead { status, error } => sqlx::query(
                "UPDATE webhook_deliveries SET status = 'dead', attempts = attempts + 1, last_status = $2, last_error = $3 \
                 WHERE delivery_id = $1",
            )
            .bind(id)
            .bind(status.map(i32::from))
            .bind(error),
        };
        let n = q.execute(&self.pg.pool).await.map_err(db)?.rows_affected();
        if n == 0 {
            return Err(not_found("webhook_delivery", id));
        }
        Ok(())
    }

    /// Number of deliveries of `run` that ended `dead`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn webhook_dead_count(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM webhook_deliveries WHERE run_id = $1 AND status = 'dead'",
        )
        .bind(run.0)
        .fetch_one(&self.pg.pool)
        .await
        .map_err(db)?;
        conv(n, "count")
    }

    /// Every delivery of `run`, ordered by `(event_seq, delivery_id)`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or a row holds an unknown status label.
    pub async fn webhook_list(&self, run: CrawlRunId) -> Result<Vec<WebhookDelivery>, StoreError> {
        let sql = format!(
            "SELECT {WEBHOOK_COLS} FROM webhook_deliveries WHERE run_id = $1 ORDER BY event_seq, delivery_id"
        );
        let rows = sqlx::query(&sql)
            .bind(run.0)
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut deliveries = Vec::with_capacity(rows.len());
        for row in &rows {
            deliveries.push(delivery_from_row(&self.pg, row).await?);
        }
        Ok(deliveries)
    }
}
