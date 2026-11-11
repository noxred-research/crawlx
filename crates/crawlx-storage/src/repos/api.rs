//! SQL behind the API's own persistence: `api_keys`,
//! `idempotency_keys`, `approvals`, `transitions` (joined with their action), replay
//! tagging on `crawl_runs`, `authorization_records` and the `webhook_deliveries` outbox.
//!
//! [`ApiRepo`] is the only place these tables are queried; `crawlx-api` maps the row
//! types here onto its own wire types. Enum columns are bound as text and read back as
//! `col::text`.
//!
//! Every statement of the request surface runs under the tenancy of [`crate::Store::scope`]:
//! PostgreSQL enforces it with row-level security, MariaDB and SQLite with the predicate of
//! [`crate::tenant::TenantGuard`] in the statement, and a request handle without a tenant
//! scope fails closed. Statements run only through [`crate::tenant::ScopedQuery`]; the module
//! denies the raw statement entry points (see `clippy.toml`).

#![deny(clippy::disallowed_methods)]

use crate::backend::strategy::{Row, WebhookClaim};
use crate::backend::{Dialect, LockMode, PgBackend, RowLock};
use crate::codec::conv;
use crate::error::not_found;
use crate::sql::{Sql, SqlRow, Stmt};
use crate::store::Store;
use crate::tenant::{Dia, ScopedQuery, Tenancy};
use crawlx_core::counters::ActionStatus;
use crawlx_core::hash::Digest;
use crawlx_core::traffic::TrustLane;
use crawlx_core::{
    ActionId, ApprovalId, CrawlRunId, NetworkEpochId, SessionId, StateId, StoreError, TenantId, Timestamp,
    TransitionId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

/// Outcome of [`ApiRepo::idem_begin`].
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

/// Result of [`ApiRepo::approval_decide`].
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

fn approval_from_row<R: SqlRow>(r: &R) -> Result<ApprovalRecord, StoreError> {
    let decision = r.text("decision")?;
    Ok(ApprovalRecord {
        id: ApprovalId(r.uuid("approval_id")?),
        run: CrawlRunId(r.uuid("run_id")?),
        action: ActionId(r.uuid("action_id")?),
        risk_class: r.text("risk_class")?,
        summary: r.json("summary")?,
        decision: ApprovalDecision::parse(&decision)
            .ok_or_else(|| serialization(format!("unknown approval decision {decision:?}")))?,
        requested_at: r.ts("requested_at")?,
        expires_at: r.ts("expires_at")?,
        decided_by: r.opt_uuid("decided_by")?,
        decided_at: r.opt_ts("decided_at")?,
        reason: r.opt_text("reason")?,
        consumed_at: r.opt_ts("consumed_at")?,
    })
}

pub(crate) async fn approval_in_transaction<B: Sql>(
    conn: &mut crate::backend::strategy::Conn<B>,
    id: ApprovalId,
) -> Result<ApprovalRecord, StoreError> {
    let sql = format!("SELECT {APPROVAL_COLS} FROM approvals WHERE approval_id=$1");
    let row = ScopedQuery::within_scope(Stmt::<B>::dynamic(&sql).uuid(id.0))
        .fetch_one(conn)
        .await?;
    approval_from_row(&row)
}

const WEBHOOK_COLS: &str =
    "delivery_id, run_id, event_seq, event_type, url, status, attempts, next_attempt_at, delivered_at, last_status, last_error";

async fn delivery_from_row<B: Sql, R: SqlRow>(
    store: &Store<B>,
    r: &R,
) -> Result<WebhookDelivery, StoreError> {
    let run = CrawlRunId(r.uuid("run_id")?);
    let id = r.uuid("delivery_id")?;
    let (tenant, zdr) = store.privacy_scope(run).await?;
    let url = if zdr {
        store
            .ephemeral_get(tenant, run, i64::MIN + 2, &format!("webhook_{id}"))
            .await?
    } else {
        r.text("url")?
    };
    let status = r.text("status")?;
    Ok(WebhookDelivery {
        id,
        run,
        event_seq: conv(r.i64("event_seq")?, "event_seq")?,
        event_type: r.text("event_type")?,
        url,
        status: DeliveryStatus::parse(&status)
            .ok_or_else(|| serialization(format!("unknown delivery status {status:?}")))?,
        attempts: conv(r.i16("attempts")?, "attempts")?,
        next_attempt_at: r.ts("next_attempt_at")?,
        delivered_at: r.opt_ts("delivered_at")?,
        last_status: r
            .opt_i32("last_status")?
            .map(|s| conv(s, "last_status"))
            .transpose()?,
        last_error: r.opt_text("last_error")?,
    })
}

fn transition_from_row<R: SqlRow>(r: &R) -> Result<TransitionRecord, StoreError> {
    Ok(TransitionRecord {
        id: TransitionId(r.uuid("transition_id")?),
        session: SessionId(r.uuid("session_id")?),
        role: r.text("role")?,
        before: StateId(r.uuid("before_state_id")?),
        after: r.opt_uuid("after_state_id")?.map(StateId),
        network_epoch: r.opt_uuid("network_epoch_id")?.map(NetworkEpochId),
        lane: crate::codec::parse_label(&r.text("lane")?)?,
        settle: r.opt_json("settle_report")?,
        action: ActionSummary {
            id: ActionId(r.uuid("action_id")?),
            seq: conv(r.i64("seq")?, "seq")?,
            kind: r.text("kind")?,
            status: crate::codec::parse_label(&r.text("status")?)?,
            lane: Some(crate::codec::parse_label(&r.text("action_lane")?)?),
            fidelity: r.opt_text("fidelity")?,
            strategy: r.text("strategy")?,
            strategy_version: conv(r.i32("strategy_version")?, "strategy_version")?,
            context_id: r.text("context_id")?,
            risk_class: r.opt_text("risk_class")?,
            safety_verdict: r.opt_text("verdict")?,
        },
        created_at: r.ts("created_at")?,
    })
}

/// A tenant row inserted when absent; the shared first step of key and record registration.
pub(crate) async fn ensure_tenant_on<B: Sql>(
    conn: &mut crate::backend::strategy::Conn<B>,
    tenant: TenantId,
    name: &str,
) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO tenants (tenant_id, name, kms_key_id) VALUES ($1, $2, 'local') {}",
        Dia::<B>::upsert_do_nothing(&["tenant_id"])
    );
    ScopedQuery::within_scope(Stmt::<B>::dynamic(&sql).uuid(tenant.0).text(name))
        .execute(conn)
        .await?;
    Ok(())
}

/// An `INSERT` that leaves an existing row alone, in a form whose `rows_affected` says whether
/// it inserted. PostgreSQL and SQLite use `ON CONFLICT DO NOTHING`; MariaDB's equivalent
/// (`ON DUPLICATE KEY UPDATE`) reports a matched row as affected, so it inserts from a
/// `SELECT .. WHERE NOT EXISTS` instead. `values` pairs every column with its expression
/// (`$n` or a literal); `key` names the unique key columns among them.
pub(crate) fn insert_if_absent<B: Sql>(table: &str, values: &[(&str, &str)], key: &[&str]) -> String {
    let columns = values.iter().map(|(col, _)| *col).collect::<Vec<_>>().join(", ");
    let exprs = values
        .iter()
        .map(|(_, expr)| *expr)
        .collect::<Vec<_>>()
        .join(", ");
    if B::KIND == crate::backend::BackendKind::MariaDb {
        let same_key = key
            .iter()
            .filter_map(|col| values.iter().find(|(name, _)| name == col))
            .map(|(col, expr)| format!("{col} = {expr}"))
            .collect::<Vec<_>>()
            .join(" AND ");
        format!(
            "INSERT INTO {table} ({columns}) SELECT {exprs} FROM DUAL \
             WHERE NOT EXISTS (SELECT 1 FROM {table} WHERE {same_key})"
        )
    } else {
        format!(
            "INSERT INTO {table} ({columns}) VALUES ({exprs}) {}",
            Dia::<B>::upsert_do_nothing(key)
        )
    }
}

/// Repository for the API-owned tables over a [`Store`].
#[derive(Clone, Debug)]
pub struct ApiRepo<B: Tenancy = PgBackend> {
    pub(super) store: Store<B>,
}

/// The PostgreSQL instantiation of [`ApiRepo`].
pub type PgApiRepo = ApiRepo<PgBackend>;

impl<B: Tenancy> ApiRepo<B> {
    /// API-table access over `store`.
    #[must_use]
    pub const fn new(store: Store<B>) -> Self {
        Self { store }
    }

    // ---- API keys -------------------------------------------------------

    /// The key whose prefix is `prefix`; `None` when absent. This is the one statement of the
    /// request surface that runs without a tenant: it authenticates the request that
    /// then carries the key's tenant. PostgreSQL runs it through the narrow
    /// `crawlx_authenticate_key` function on the restricted request role; the other engines
    /// read exactly the same columns by the unique prefix.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or the stored hash is not 32 bytes.
    pub async fn key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKeyRow>, StoreError> {
        let _timer = self.store.query_timer("api.key_by_prefix");
        let source = if B::KIND == crate::backend::BackendKind::Postgres {
            "crawlx_authenticate_key($1)"
        } else {
            "api_keys WHERE prefix = $1"
        };
        let sql = format!(
            "SELECT key_id, tenant_id, prefix, key_hash, scopes, expires_at, revoked_at FROM {source}"
        );
        let pool = B::pre_auth_pool(&self.store.pool);
        let row = ScopedQuery::pre_authentication(Stmt::<B>::dynamic(&sql).text(prefix))
            .fetch_optional_pool(&pool)
            .await?;
        let Some(r) = row else { return Ok(None) };
        let hash = r.bytes("key_hash")?;
        let hash: [u8; 32] = hash.try_into().map_err(|h: Vec<u8>| {
            serialization(format!("api key hash has {} bytes, expected 32", h.len()))
        })?;
        Ok(Some(ApiKeyRow {
            key_id: r.uuid("key_id")?,
            tenant: TenantId(r.uuid("tenant_id")?),
            prefix: r.text("prefix")?,
            hash,
            scopes: r.text_list("scopes")?,
            expires_at: r.opt_ts("expires_at")?,
            revoked: r.opt_ts("revoked_at")?.is_some(),
        }))
    }

    /// Insert `key` after ensuring its tenant exists (named `tenant_name`). Idempotent on
    /// `prefix`: an existing row wins.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the tenant upsert or the insert fails.
    pub async fn key_insert(&self, key: &ApiKeyRow, tenant_name: &str) -> Result<(), StoreError> {
        let _timer = self.store.query_timer("api.key_insert");
        let scope = self.store.scope()?;
        scope.authorize(key.tenant)?;
        let mut tx = self.store.begin_write().await?;
        ensure_tenant_on::<B>(tx.conn(), key.tenant, tenant_name).await?;
        let sql = format!(
            "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes, expires_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN {} END) {}",
            Dia::<B>::now(),
            Dia::<B>::upsert_do_nothing(&["prefix"])
        );
        scope
            .query(
                "api_keys",
                Stmt::<B>::dynamic(&sql)
                    .uuid(key.key_id)
                    .uuid(key.tenant.0)
                    .text(&key.prefix)
                    .bytes(key.hash.as_slice())
                    .text_list(&key.scopes)
                    .opt_ts(key.expires_at)
                    .bool(key.revoked),
            )?
            .execute(tx.conn())
            .await?;
        tx.commit().await
    }

    /// Set `api_keys.last_used_at` of `key_id` to `at`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the update fails.
    pub async fn key_touch(&self, key_id: Uuid, at: Timestamp) -> Result<(), StoreError> {
        let _timer = self.store.query_timer("api.key_touch");
        let scope = self.store.scope()?;
        let sql = format!(
            "UPDATE api_keys SET last_used_at = $2 WHERE key_id = $1{}",
            scope.and("api_keys", "", 3)?
        );
        scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(key_id).ts(at))
            .execute_write(&self.store.pool)
            .await?;
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
        let _timer = self.store.query_timer("api.idem_begin");
        let scope = self.store.scope()?;
        scope.authorize(tenant)?;
        let insert = insert_if_absent::<B>(
            "idempotency_keys",
            &[
                ("tenant_id", "$1"),
                ("idem_key", "$2"),
                ("request_hash", "$3"),
                ("state", "'in_progress'"),
                ("expires_at", "$4"),
            ],
            &["tenant_id", "idem_key"],
        );
        // A concurrent release/expiry can remove the row between the INSERT and the SELECT; retry.
        for _ in 0..3 {
            let mut tx = self.store.begin_write().await?;
            scope
                .query(
                    "idempotency_keys",
                    Stmt::<B>::dynamic(
                        "DELETE FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2 AND expires_at <= $3",
                    )
                    .uuid(tenant.0)
                    .text(key)
                    .ts(now),
                )?
                .execute(tx.conn())
                .await?;
            let expires = now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS);
            let inserted = scope
                .query(
                    "idempotency_keys",
                    Stmt::<B>::dynamic(&insert)
                        .uuid(tenant.0)
                        .text(key)
                        .bytes(request_hash.0.as_slice())
                        .ts(expires),
                )?
                .execute(tx.conn())
                .await;
            let inserted = match inserted {
                Ok(n) => n,
                // two claimers racing the same key on an engine that reports the duplicate as
                // an error: the loser reads the winner's row below
                Err(StoreError::Conflict(_)) if B::KIND == crate::backend::BackendKind::MariaDb => 0,
                Err(error) => return Err(error),
            };
            if inserted == 1 {
                tx.commit().await?;
                return Ok(IdemClaim::Started);
            }
            let row = scope
                .query(
                    "idempotency_keys",
                    Stmt::<B>::dynamic(
                        "SELECT request_hash, state, response_status, response_body, run_id FROM idempotency_keys \
                         WHERE tenant_id = $1 AND idem_key = $2",
                    )
                    .uuid(tenant.0)
                    .text(key),
                )?
                .fetch_optional(tx.conn())
                .await?;
            tx.commit().await?;
            let Some(r) = row else { continue };
            let stored_hash = r.bytes("request_hash")?;
            if stored_hash.as_slice() != request_hash.0.as_slice() {
                return Ok(IdemClaim::Mismatch);
            }
            let state = r.text("state")?;
            return match state.as_str() {
                "in_progress" => Ok(IdemClaim::InProgress),
                "done" => {
                    let status = r
                        .opt_i32("response_status")?
                        .ok_or_else(|| serialization("completed idempotency key without response_status"))?;
                    let body = r.opt_json("response_body")?;
                    let run_id = r.opt_uuid("run_id")?;
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
        let _timer = self.store.query_timer("api.idem_complete");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(());
        }
        scope
            .query(
                "idempotency_keys",
                Stmt::<B>::dynamic(
                    "UPDATE idempotency_keys SET state = 'done', response_status = $3, response_body = $4, run_id = $5 \
                     WHERE tenant_id = $1 AND idem_key = $2",
                )
                .uuid(tenant.0)
                .text(key)
                .i32(i32::from(response.status))
                .json(&response.body)
                .opt_uuid(response.run_id.map(|r| r.0)),
            )?
            .execute_write(&self.store.pool)
            .await?;
        Ok(())
    }

    /// Drop the `in_progress` claim on `key`; completed keys are kept.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the delete fails.
    pub async fn idem_release(&self, tenant: TenantId, key: &str) -> Result<(), StoreError> {
        let _timer = self.store.query_timer("api.idem_release");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(());
        }
        scope
            .query(
                "idempotency_keys",
                Stmt::<B>::dynamic(
                    "DELETE FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2 AND state = 'in_progress'",
                )
                .uuid(tenant.0)
                .text(key),
            )?
            .execute_write(&self.store.pool)
            .await?;
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
        let _timer = self.store.query_timer("api.idem_link_run");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(());
        }
        // The run must belong to the tenant on every engine: the foreign key to `crawl_runs`
        // is not row-level-security checked, so PostgreSQL's policies alone would let a tenant
        // link another tenant's run.
        let sql = "UPDATE idempotency_keys SET run_id = $3 WHERE tenant_id = $1 AND idem_key = $2 \
                   AND state = 'in_progress' \
                   AND EXISTS (SELECT 1 FROM crawl_runs scope_r WHERE scope_r.run_id = $3 AND scope_r.tenant_id = $1)";
        scope
            .query(
                "idempotency_keys",
                Stmt::<B>::dynamic(sql).uuid(tenant.0).text(key).uuid(run.0),
            )?
            .execute_write(&self.store.pool)
            .await?;
        Ok(())
    }

    /// The run linked to `key`: the one an `in_progress` claim announced
    /// ([`Self::idem_link_run`]) or the one a completed claim created. `None` when the key is
    /// unknown or carries no run.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn idem_run(&self, tenant: TenantId, key: &str) -> Result<Option<CrawlRunId>, StoreError> {
        let _timer = self.store.query_timer("api.idem_run");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let row = scope
            .query(
                "idempotency_keys",
                Stmt::<B>::dynamic(
                    "SELECT run_id FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2",
                )
                .uuid(tenant.0)
                .text(key),
            )?
            .fetch_optional_pool(&self.store.pool)
            .await?;
        row.map(|r| r.opt_uuid("run_id"))
            .transpose()
            .map(|run| run.flatten().map(CrawlRunId))
    }

    // ---- approvals --------------------------------------------------------

    /// Every approval of `run`, ordered by approval id.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or a row holds an unknown decision label.
    pub async fn approvals_list(&self, run: CrawlRunId) -> Result<Vec<ApprovalRecord>, StoreError> {
        let _timer = self.store.query_timer("api.approvals_list");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT {APPROVAL_COLS} FROM approvals WHERE run_id = $1{} ORDER BY approval_id",
            scope.and("approvals", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
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
        let _timer = self.store.query_timer("api.approval_get");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT {APPROVAL_COLS} FROM approvals WHERE run_id = $1 AND approval_id = $2{}",
            scope.and("approvals", "", 3)?
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0).uuid(id.0))
            .fetch_optional_pool(&self.store.pool)
            .await?;
        row.as_ref().map(approval_from_row).transpose()
    }

    /// Apply `Approved` or `Denied` to a pending, unexpired, unconsumed approval.
    /// Approval preserves the hold: only fenced verified T1 may release it.
    /// Durable decision time comes from the database after acquiring the row lock.
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
        _now: Timestamp,
    ) -> Result<DecideOutcome, StoreError> {
        let _timer = self.store.query_timer("api.approval_decide");
        let hold = match decision {
            ApprovalDecision::Approved => "awaiting_approval",
            ApprovalDecision::Denied => "denied",
            ApprovalDecision::Pending | ApprovalDecision::Expired => {
                return Err(StoreError::Conflict(format!(
                    "an approval cannot be decided as {}",
                    decision.as_str()
                )))
            }
        };
        let scope = self.store.scope()?;
        let mut tx = self.store.begin_write().await?;
        let zdr = if crate::repos::effects::in_rust::<B>() {
            Store::<B>::privacy_scope_tx(tx.conn(), run).await?.1
        } else {
            false
        };
        let reason = reason.map(|text| crate::zdr_project::approval_reason(text, zdr));
        let reason = reason.as_deref();
        let sql = format!(
            "SELECT {APPROVAL_COLS}, revoked_at FROM approvals WHERE run_id = $1 AND approval_id = $2{}{}",
            scope.and("approvals", "", 3)?,
            Dia::<B>::row_lock(RowLock::Update)
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0).uuid(id.0))
            .fetch_optional(tx.conn())
            .await?;
        let Some(row) = row else {
            return Ok(DecideOutcome::NotFound);
        };
        let current = approval_from_row(&row)?;
        let revoked = row.opt_ts("revoked_at")?.is_some();
        let now = crate::sql::db_clock::<B>(tx.conn()).await?;
        if current.decision == decision
            && current.expires_at > now
            && current.consumed_at.is_none()
            && !revoked
        {
            return Ok(DecideOutcome::Unchanged(current));
        }
        if current.decision != ApprovalDecision::Pending
            || current.expires_at <= now
            || current.consumed_at.is_some()
            || revoked
        {
            return Ok(DecideOutcome::NotPending(current));
        }
        let update = "UPDATE approvals SET decision = $2, decided_by = $3, decided_at = $4, reason = $5 \
                      WHERE approval_id = $1";
        let updated = if <Dia<B> as Dialect>::UPDATE_RETURNING {
            let sql = format!("{update} RETURNING {APPROVAL_COLS}");
            scope
                .query(
                    "approvals",
                    Stmt::<B>::dynamic(&sql)
                        .uuid(id.0)
                        .text(decision.as_str())
                        .uuid(decided_by)
                        .ts(now)
                        .opt_text(reason),
                )?
                .fetch_one(tx.conn())
                .await?
        } else {
            scope
                .query(
                    "approvals",
                    Stmt::<B>::dynamic(update)
                        .uuid(id.0)
                        .text(decision.as_str())
                        .uuid(decided_by)
                        .ts(now)
                        .opt_text(reason),
                )?
                .execute(tx.conn())
                .await?;
            let sql = format!("SELECT {APPROVAL_COLS} FROM approvals WHERE approval_id = $1");
            scope
                .query("approvals", Stmt::<B>::dynamic(&sql).uuid(id.0))?
                .fetch_one(tx.conn())
                .await?
        };
        let updated = approval_from_row(&updated)?;
        let hold_sql = format!(
            "UPDATE actions SET hold = $2 WHERE action_id = $1{}",
            scope.and("actions", "", 3)?
        );
        scope
            .bind(Stmt::<B>::dynamic(&hold_sql).uuid(updated.action.0).text(hold))
            .execute(tx.conn())
            .await?;
        tx.commit().await?;
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
        let _timer = self.store.query_timer("api.transitions_list");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT t.transition_id, t.session_id, s.role, t.before_state_id, t.after_state_id, t.network_epoch_id, \
                    t.lane::text AS lane, t.settle_report, t.created_at, \
                    a.action_id, a.seq, a.action_kind::text AS kind, a.status::text AS status, a.lane::text AS action_lane, \
                    a.fidelity::text AS fidelity, a.strategy, a.strategy_version, \
                    {} AS context_id, sd.risk_class::text AS risk_class, sd.verdict \
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
               AND ($7::uuid IS NULL OR t.after_state_id = $7){} \
             ORDER BY t.transition_id",
            Dia::<B>::hex("c.context_hash"),
            scope.and("transitions", "t", 8)?
        );
        let rows = scope
            .bind(
                Stmt::<B>::dynamic(&sql)
                    .uuid(run.0)
                    .opt_uuid(filter.session.map(|s| s.0))
                    .opt_text(filter.role.as_deref())
                    .opt_text(filter.lane.map(TrustLane::as_str))
                    .opt_text(filter.status.map(ActionStatus::as_str))
                    .opt_uuid(filter.from_state.map(|s| s.0))
                    .opt_uuid(filter.to_state.map(|s| s.0)),
            )
            .fetch_all_pool(&self.store.pool)
            .await?;
        rows.iter().map(transition_from_row).collect()
    }

    // ---- runs -------------------------------------------------------------

    /// Number of runs of `tenant` in `queued|running|pausing|paused`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn active_run_count(&self, tenant: TenantId) -> Result<u64, StoreError> {
        let _timer = self.store.query_timer("api.active_run_count");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(0);
        }
        let row = scope
            .query(
                "crawl_runs",
                Stmt::<B>::dynamic(
                    "SELECT count(*) AS v FROM crawl_runs WHERE tenant_id = $1 AND status::text IN ('queued','running','pausing','paused')",
                )
                .uuid(tenant.0),
            )?
            .fetch_one_pool(&self.store.pool)
            .await?;
        conv(row.i64("v")?, "count")
    }

    /// Ids of the runs of `tenant` in `queued|running|pausing|paused`, oldest first.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn active_runs(&self, tenant: TenantId) -> Result<Vec<CrawlRunId>, StoreError> {
        let _timer = self.store.query_timer("api.active_runs");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(Vec::new());
        }
        let rows = scope
            .query(
                "crawl_runs",
                Stmt::<B>::dynamic(
                    "SELECT run_id FROM crawl_runs WHERE tenant_id = $1 AND status::text IN ('queued','running','pausing','paused') ORDER BY created_at, run_id",
                )
                .uuid(tenant.0),
            )?
            .fetch_all_pool(&self.store.pool)
            .await?;
        rows.iter().map(|r| Ok(CrawlRunId(r.uuid("run_id")?))).collect()
    }

    /// Mark `run` as `run_kind = 'shadow'` (a mirrored crawl).
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when `run` does not exist (or belongs to another
    /// tenant) and other [`StoreError`]s if the update fails.
    pub async fn shadow_tag(&self, run: CrawlRunId) -> Result<(), StoreError> {
        let _timer = self.store.query_timer("api.shadow_tag");
        let scope = self.store.scope()?;
        let sql = format!(
            "UPDATE crawl_runs SET run_kind = 'shadow' WHERE run_id = $1{}",
            scope.and("crawl_runs", "", 2)?
        );
        let n = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .execute_write(&self.store.pool)
            .await?;
        if n == 0 {
            return Err(not_found("crawl_run", run));
        }
        Ok(())
    }

    // ---- webhook outbox -----------------------------------------------------

    /// Runs whose configuration carries a webhook URL (`config.output.webhook.url`), in
    /// run-id order. Operator work: it spans tenants.
    ///
    /// # Errors
    /// Returns [`StoreError::AccessDenied`] on a request handle and other [`StoreError`]s if
    /// the query fails.
    pub async fn webhook_runs(&self) -> Result<Vec<CrawlRunId>, StoreError> {
        let _timer = self.store.query_timer("api.webhook_runs");
        self.store.require_operator()?;
        let url = Dia::<B>::json_text(
            &Dia::<B>::json_extract(&Dia::<B>::json_extract("config", "output"), "webhook"),
            "url",
        );
        let configured = Dia::<B>::json_text("config", "webhookConfigured");
        // SQLite's `->>` yields 1 for a JSON `true`; the other engines yield the text
        let flag = if B::KIND == crate::backend::BackendKind::Sqlite {
            format!("({configured} = 'true' OR {configured} = 1)")
        } else {
            format!("{configured} = 'true'")
        };
        let sql = format!(
            "SELECT run_id FROM crawl_runs WHERE {url} IS NOT NULL \
             OR (retention_mode = 'zdr' AND {flag}) ORDER BY run_id"
        );
        let rows = self
            .store
            .scope()?
            .query("crawl_runs", Stmt::<B>::dynamic(&sql))?
            .fetch_all_pool(&self.store.pool)
            .await?;
        rows.iter().map(|r| Ok(CrawlRunId(r.uuid("run_id")?))).collect()
    }

    /// Highest `event_seq` queued for `run`; `0` when none.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails.
    pub async fn webhook_cursor(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let _timer = self.store.query_timer("api.webhook_cursor");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT COALESCE(max(event_seq), 0) AS v FROM webhook_deliveries WHERE run_id = $1{}",
            scope.and("webhook_deliveries", "", 2)?
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_one_pool(&self.store.pool)
            .await?;
        conv(row.i64("v")?, "event_seq")
    }

    /// Queue `d`; `false` when `(run, event_seq, url)` is already queued.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] when `event_seq` or `attempts` do not fit their
    /// columns, [`StoreError::NotFound`] for a run the scope does not own and other
    /// [`StoreError`]s if the transaction fails.
    pub async fn webhook_enqueue(&self, d: &WebhookDelivery) -> Result<bool, StoreError> {
        let _timer = self.store.query_timer("api.webhook_enqueue");
        let event_seq: i64 = conv(d.event_seq, "event_seq")?;
        let attempts: i16 = conv(d.attempts, "attempts")?;
        let scope = self.store.scope()?;
        let (tenant, zdr) = self.store.owned_privacy_scope(&scope, d.run).await?;
        let durable_url = if zdr {
            self.store
                .ephemeral_put(tenant, d.run, i64::MIN + 2, &format!("webhook_{}", d.id), &d.url)
                .await?;
            Digest::of("crawlx/zdr-webhook-url/v1", d.url.as_bytes()).to_hex()
        } else {
            d.url.clone()
        };
        let mut tx = self.store.begin_write().await?;
        // `webhook_deliveries` has no unique key over (run, event_seq, url); serialize racing enqueuers.
        let lock = format!("webhook:{}:{}:{}", d.run.0, event_seq, durable_url);
        B::xact_lock(tx.conn(), &lock, LockMode::Exclusive).await?;
        let from = if B::KIND == crate::backend::BackendKind::MariaDb {
            " FROM DUAL"
        } else {
            ""
        };
        let sql = format!(
            "INSERT INTO webhook_deliveries (delivery_id, run_id, event_seq, event_type, url, status, attempts, \
               next_attempt_at, delivered_at, last_status, last_error) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11{from} \
             WHERE NOT EXISTS (SELECT 1 FROM webhook_deliveries WHERE run_id = $2 AND event_seq = $3 AND url = $5){}",
            scope.and_run_owned("$2", 12)
        );
        let n = scope
            .bind(
                Stmt::<B>::dynamic(&sql)
                    .uuid(d.id)
                    .uuid(d.run.0)
                    .i64(event_seq)
                    .text(&d.event_type)
                    .text(&durable_url)
                    .text(d.status.as_str())
                    .i16(attempts)
                    .ts(d.next_attempt_at)
                    .opt_ts(d.delivered_at)
                    .opt_i32(d.last_status.map(i32::from))
                    .opt_text(d.last_error.as_deref()),
            )
            .execute(tx.conn())
            .await?;
        tx.commit().await?;
        Ok(n == 1)
    }

    /// Claim up to `limit` pending deliveries due at `now` (`SKIP LOCKED`), deferring each
    /// by `lease_secs`; returned in `(due_at, delivery_id)` order. Operator work: the claim
    /// spans tenants.
    ///
    /// # Errors
    /// Returns [`StoreError::AccessDenied`] on a request handle, and a [`StoreError`] if the
    /// statement fails or a row holds an unknown status label or an out-of-range counter.
    pub async fn webhook_claim_due(
        &self,
        now: Timestamp,
        limit: u32,
        lease_secs: u32,
    ) -> Result<Vec<WebhookDelivery>, StoreError>
    where
        Row<B>: SqlRow,
    {
        let _timer = self.store.query_timer("api.webhook_claim_due");
        self.store.require_operator()?;
        let scope = self.store.scope()?;
        let rows = B::claim_webhooks(
            &self.store.pool,
            WebhookClaim {
                now,
                limit: i64::from(limit),
                lease_secs: f64::from(lease_secs),
                columns: WEBHOOK_COLS,
            },
        )
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            match delivery_from_row(&self.store, row).await {
                Ok(delivery) => out.push((row.ts("due_at")?, delivery)),
                Err(StoreError::RetentionDenied(_)) => {
                    // Expired volatile content cannot be delivered. Do not let one expired
                    // ZDR receiver block unrelated tenants' durable deliveries.
                    // only a zero-retention run's delivery can expire; engines without the
                    // trigger store the digest of the text
                    let error = if crate::repos::effects::in_rust::<B>() {
                        crate::zdr_project::webhook_error(crate::zdr_project::EXPIRED_DELIVERY_ERROR, true)
                    } else {
                        std::borrow::Cow::Borrowed(crate::zdr_project::EXPIRED_DELIVERY_ERROR)
                    };
                    scope
                        .query(
                            "webhook_deliveries",
                            Stmt::<B>::dynamic(
                                "UPDATE webhook_deliveries SET status = 'dead', last_error = $2 \
                                 WHERE delivery_id = $1 AND status = 'pending'",
                            )
                            .uuid(row.uuid("delivery_id")?)
                            .text(&error),
                        )?
                        .execute_write(&self.store.pool)
                        .await?;
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
        let _timer = self.store.query_timer("api.webhook_record");
        let scope = self.store.scope()?;
        // engines without the PostgreSQL trigger project the failure text of a zero-retention
        // run before it is stored
        let zdr = if crate::repos::effects::in_rust::<B>()
            && matches!(result, DeliveryResult::Retry { .. } | DeliveryResult::Dead { .. })
        {
            scope
                .query(
                    "webhook_deliveries",
                    Stmt::<B>::dynamic(
                        "SELECT c.retention_mode::text AS mode FROM webhook_deliveries w \
                         JOIN crawl_runs c ON c.run_id = w.run_id WHERE w.delivery_id = $1",
                    )
                    .uuid(id),
                )?
                .fetch_optional_pool(&self.store.pool)
                .await?
                .map(|r| r.text("mode"))
                .transpose()?
                .is_some_and(|mode| mode == "zdr")
        } else {
            false
        };
        let n = match result {
            DeliveryResult::Delivered { status, at } => {
                let sql = format!(
                    "UPDATE webhook_deliveries SET status = 'delivered', attempts = attempts + 1, delivered_at = $2, \
                       last_status = $3, last_error = NULL WHERE delivery_id = $1{}",
                    scope.and("webhook_deliveries", "", 4)?
                );
                scope
                    .bind(Stmt::<B>::dynamic(&sql).uuid(id).ts(*at).i32(i32::from(*status)))
                    .execute_write(&self.store.pool)
                    .await?
            }
            DeliveryResult::Retry {
                status,
                error,
                next_attempt_at,
            } => {
                let sql = format!(
                    "UPDATE webhook_deliveries SET status = 'pending', attempts = attempts + 1, next_attempt_at = $2, \
                       last_status = $3, last_error = $4 WHERE delivery_id = $1{}",
                    scope.and("webhook_deliveries", "", 5)?
                );
                scope
                    .bind(
                        Stmt::<B>::dynamic(&sql)
                            .uuid(id)
                            .ts(*next_attempt_at)
                            .opt_i32(status.map(i32::from))
                            .text(&crate::zdr_project::webhook_error(error, zdr)),
                    )
                    .execute_write(&self.store.pool)
                    .await?
            }
            DeliveryResult::Dead { status, error } => {
                let sql = format!(
                    "UPDATE webhook_deliveries SET status = 'dead', attempts = attempts + 1, last_status = $2, last_error = $3 \
                     WHERE delivery_id = $1{}",
                    scope.and("webhook_deliveries", "", 4)?
                );
                scope
                    .bind(
                        Stmt::<B>::dynamic(&sql)
                            .uuid(id)
                            .opt_i32(status.map(i32::from))
                            .text(&crate::zdr_project::webhook_error(error, zdr)),
                    )
                    .execute_write(&self.store.pool)
                    .await?
            }
        };
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
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT count(*) AS v FROM webhook_deliveries WHERE run_id = $1 AND status = 'dead'{}",
            scope.and("webhook_deliveries", "", 2)?
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_one_pool(&self.store.pool)
            .await?;
        conv(row.i64("v")?, "count")
    }

    /// Every delivery of `run`, ordered by `(event_seq, delivery_id)`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the query fails or a row holds an unknown status label.
    pub async fn webhook_list(&self, run: CrawlRunId) -> Result<Vec<WebhookDelivery>, StoreError> {
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT {WEBHOOK_COLS} FROM webhook_deliveries WHERE run_id = $1{} ORDER BY event_seq, delivery_id",
            scope.and("webhook_deliveries", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_all_pool(&self.store.pool)
            .await?;
        let mut deliveries = Vec::with_capacity(rows.len());
        for row in &rows {
            deliveries.push(delivery_from_row(&self.store, row).await?);
        }
        Ok(deliveries)
    }
}
