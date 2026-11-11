//! `ActionJournal`: T1 intent, T2 outcome, reaper `unknown`, reconciliation.
//!
//! Generic over the engine. Statements run in one write transaction; where PostgreSQL has a
//! single statement the other engines cannot run (`FOR UPDATE OF`, `UPDATE .. FROM ..
//! RETURNING`, `jsonb` merge, `UNNEST`), PostgreSQL keeps its statement byte for byte and the
//! other engines run the same steps as separate statements under the same row lock.

use super::event::append_event;
use super::ledger::{ensure_context, key_from_row, KEY_COLS};
use super::safety::write_decision;
use super::state::insert_state;
use crate::backend::strategy::{Conn, FenceSeq, TrafficRow};
use crate::backend::{BackendKind, Dialect, RowLock};
use crate::chaos;
use crate::codec::{conv, origin_label, parse_label, to_json};
use crate::error::not_found;
use crate::sql::{in_ids, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::counters::ActionStatus;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::{ActionJournal, ActionRecord, JournalOutcomes, OutcomeRecord, Reconciliation};
use crawlx_core::safety::{SafetyDecision, SafetyVerdict};
use crawlx_core::traffic::TrustLane;
use crawlx_core::{
    ActionId, CrawlRunId, ModelDecisionId, SafetyDecisionId, SessionId, StateId, StoreError, Timestamp,
    TraceId, TransitionId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use uuid::Uuid;

/// How long a pending approval stays valid (24 h).
const APPROVAL_TTL_HOURS: i32 = 24;

const ACTION_SELECT: &str = "SELECT a.action_id, a.run_id, a.session_id, a.seq, a.status::text AS status, a.attempt, a.strategy, a.strategy_version, \
    a.epoch_navigation, a.epoch_document, a.epoch_mutation, a.fidelity::text AS fidelity, a.lane::text AS lane, a.safety_decision_id, \
    a.model_decision_id, a.before_state_id, a.reconcile_resolution, a.proposed_at, a.intended_at, a.finished_at, a.trace_id, ";

async fn record_from_row<B: Sql>(store: &Store<B>, r: &B::Row) -> Result<ActionRecord, StoreError> {
    let strategy = if r.flag("context_zdr")? {
        let tenant = crawlx_core::TenantId(r.uuid("context_tenant_id")?);
        let run = CrawlRunId(r.uuid("run_id")?);
        let action = ActionId(r.uuid("action_id")?);
        store
            .ephemeral_get(tenant, run, i64::MIN + 1, &format!("_strategy:{action}"))
            .await?
    } else {
        r.text("strategy")?
    };
    Ok(ActionRecord {
        id: ActionId(r.uuid("action_id")?),
        run: CrawlRunId(r.uuid("run_id")?),
        session: SessionId(r.uuid("session_id")?),
        seq: conv(r.i64("seq")?, "seq")?,
        key: key_from_row(store, r).await?,
        status: parse_label(&r.text("status")?)?,
        attempt: conv(r.i16("attempt")?, "attempt")?,
        strategy,
        strategy_version: conv(r.i32("strategy_version")?, "strategy_version")?,
        epoch: ObservationEpoch {
            navigation_seq: conv(r.i64("epoch_navigation")?, "epoch_navigation")?,
            document_seq: conv(r.i64("epoch_document")?, "epoch_document")?,
            mutation_seq: conv(r.i64("epoch_mutation")?, "epoch_mutation")?,
        },
        lane: Some(parse_label(&r.text("lane")?)?),
        fidelity: Some(parse_label(&r.text("fidelity")?)?),
        safety_decision: SafetyDecisionId(r.uuid("safety_decision_id")?),
        model_decision: r.opt_uuid("model_decision_id")?.map(ModelDecisionId),
        before_state: r.opt_uuid("before_state_id")?.map(StateId),
        reconcile_resolution: r
            .opt_text("reconcile_resolution")?
            .map(|s| parse_label(&s))
            .transpose()?,
        proposed_at: r.ts("proposed_at")?,
        intended_at: r.opt_ts("intended_at")?,
        finished_at: r.opt_ts("finished_at")?,
        trace_id: r
            .opt_text("trace_id")?
            .map(|s| TraceId::from_str(&s).map_err(|e| StoreError::Serialization(e.to_string())))
            .transpose()?,
    })
}

async fn bump_unknown<B: Sql>(conn: &mut Conn<B>, rows: &[(Uuid, i64)]) -> Result<(), StoreError> {
    let mut per_ctx: BTreeMap<i64, i32> = BTreeMap::new();
    for (_, ctx) in rows {
        *per_ctx.entry(*ctx).or_insert(0) += 1;
    }
    for (ctx, n) in per_ctx {
        stmt!(
            B,
            "UPDATE action_contexts SET unknown = unknown + $2 WHERE context_id = $1"
        )
        .i64(ctx)
        .i32(n)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// `intended → unknown` for every `intended` action of `session_ids`; bumps the ledger.
/// `finished_at` is the instant of the flip: when the outcome was declared unknown
/// (the trail verifier requires it on every final-status row).
pub(crate) async fn flip_intended_to_unknown<B: Sql>(
    conn: &mut Conn<B>,
    session_ids: &[Uuid],
) -> Result<Vec<ActionId>, StoreError> {
    if session_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut pairs: Vec<(Uuid, i64)> = Vec::new();
    if B::KIND == BackendKind::Postgres {
        let rows = stmt!(B, "UPDATE actions SET status = 'unknown', finished_at = now() WHERE session_id = ANY($1) AND status = 'intended' RETURNING action_id, context_id")
            .uuid_list(session_ids)
            .fetch_all(&mut *conn)
            .await?;
        for r in &rows {
            pairs.push((r.uuid("action_id")?, r.i64("context_id")?));
        }
    } else {
        // read the rows being flipped under the write lock, then flip exactly those sessions
        let lock = <B::Dialect as Dialect>::row_lock(RowLock::Update);
        let now = <B::Dialect as Dialect>::now();
        for chunk in session_ids.chunks(<B::Dialect as Dialect>::MAX_BIND_PARAMS.saturating_sub(8).max(1)) {
            let list = in_ids::<B>(1, chunk.len());
            let rows = Stmt::<B>::dynamic(&format!(
                "SELECT action_id, context_id FROM actions WHERE session_id {list} AND status = 'intended'{lock}"
            ))
            .uuid_list(chunk)
            .fetch_all(&mut *conn)
            .await?;
            for r in &rows {
                pairs.push((r.uuid("action_id")?, r.i64("context_id")?));
            }
            Stmt::<B>::dynamic(&format!(
                "UPDATE actions SET status = 'unknown', finished_at = {now} WHERE session_id {list} AND status = 'intended'"
            ))
            .uuid_list(chunk)
            .execute(&mut *conn)
            .await?;
        }
    }
    bump_unknown::<B>(conn, &pairs).await?;
    Ok(pairs.into_iter().map(|(a, _)| ActionId(a)).collect())
}

fn hold_for(v: &SafetyVerdict) -> &'static str {
    match v.decision {
        SafetyDecision::Allow => "none",
        SafetyDecision::Deny => "denied",
        SafetyDecision::ApprovalRequired => "awaiting_approval",
    }
}

fn update_lock<B: Sql>() -> &'static str {
    <B::Dialect as Dialect>::row_lock(RowLock::Update)
}

/// `action_seq + 1` of a session, the per-session sequence of its actions.
async fn bump_action_seq<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    session: SessionId,
) -> Result<i64, StoreError> {
    if B::KIND == BackendKind::Postgres {
        let row = stmt!(
            B,
            "UPDATE crawl_sessions SET action_seq = action_seq + 1 WHERE session_id = $1 AND run_id = $2 RETURNING action_seq"
        )
        .uuid(session.0)
        .uuid(run.0)
        .fetch_optional(conn)
        .await?;
        return row
            .map(|row| row.i64("action_seq"))
            .transpose()?
            .ok_or_else(|| not_found("crawl_session", session));
    }
    let updated = stmt!(
        B,
        "UPDATE crawl_sessions SET action_seq = action_seq + 1 WHERE session_id = $1 AND run_id = $2"
    )
    .uuid(session.0)
    .uuid(run.0)
    .execute(&mut *conn)
    .await?;
    if updated == 0 {
        return Err(not_found("crawl_session", session));
    }
    stmt!(B, "SELECT action_seq FROM crawl_sessions WHERE session_id = $1")
        .uuid(session.0)
        .fetch_one(conn)
        .await?
        .i64("action_seq")
}

/// The `actions` insert of a proposal. SQLite has no identity column for `dataset_page`, so
/// the ordinal is drawn from its sequence row and bound as `$19`.
fn action_insert_sql<B: Sql>() -> String {
    let (column, value) = if B::KIND == BackendKind::Sqlite {
        (", dataset_page", ", $19")
    } else {
        ("", "")
    };
    format!(
        "INSERT INTO actions (action_id, run_id, session_id, seq, context_id, action_kind, params, strategy, strategy_version, \
           epoch_navigation, epoch_document, epoch_mutation, fidelity, lane, safety_decision_id, model_decision_id, hold, trace_id{column}) \
         VALUES ($1, $2, $3, $4, $5, $6::text::action_kind, $7, $8, $9, $10, $11, $12, $13::text::action_fidelity, $14::text::trust_lane, $15, $16, $17, $18{value})"
    )
}

/// What `intend` reads under the action's row lock.
struct IntentRow {
    status: String,
    attempt: i16,
    hold: String,
    session: Uuid,
    context: i64,
    resolution: Option<String>,
    session_status: String,
}

async fn lock_action_for_intent<B: Sql>(conn: &mut Conn<B>, id: ActionId) -> Result<IntentRow, StoreError> {
    if B::KIND == BackendKind::Postgres {
        let row = stmt!(
            B,
            "SELECT a.status::text AS status, a.attempt, a.hold, a.session_id, a.context_id, a.reconcile_resolution, s.status AS session_status \
             FROM actions a JOIN crawl_sessions s ON s.session_id = a.session_id WHERE a.action_id = $1 FOR UPDATE OF a"
        )
        .uuid(id.0)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| not_found("action", id))?;
        return Ok(IntentRow {
            status: row.text("status")?,
            attempt: row.i16("attempt")?,
            hold: row.text("hold")?,
            session: row.uuid("session_id")?,
            context: row.i64("context_id")?,
            resolution: row.opt_text("reconcile_resolution")?,
            session_status: row.text("session_status")?,
        });
    }
    // lock the action row alone; the session status is read without a lock
    let row = Stmt::<B>::dynamic(&format!(
        "SELECT a.status, a.attempt, a.hold, a.session_id, a.context_id, a.reconcile_resolution \
         FROM actions a WHERE a.action_id = $1{}",
        update_lock::<B>()
    ))
    .uuid(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| not_found("action", id))?;
    let session = row.uuid("session_id")?;
    let session_status = stmt!(B, "SELECT status FROM crawl_sessions WHERE session_id = $1")
        .uuid(session)
        .fetch_optional(conn)
        .await?
        .map(|row| row.text("status"))
        .transpose()?
        .unwrap_or_default();
    Ok(IntentRow {
        status: row.text("status")?,
        attempt: row.i16("attempt")?,
        hold: row.text("hold")?,
        session,
        context: row.i64("context_id")?,
        resolution: row.opt_text("reconcile_resolution")?,
        session_status,
    })
}

/// What `finish` reads under the action's row lock.
struct FinishRow {
    status: String,
    run: Uuid,
    session: Uuid,
    context: i64,
    lane: String,
    before: Option<Uuid>,
    retention_mode: String,
}

async fn lock_action_for_finish<B: Sql>(conn: &mut Conn<B>, id: ActionId) -> Result<FinishRow, StoreError> {
    if B::KIND == BackendKind::Postgres {
        let row = stmt!(
            B,
            "SELECT a.status::text AS status, a.run_id, a.session_id, a.context_id, a.lane::text AS lane, a.before_state_id, r.retention_mode::text AS retention_mode \
             FROM actions a JOIN crawl_runs r ON r.run_id = a.run_id WHERE a.action_id = $1 FOR UPDATE OF a"
        )
        .uuid(id.0)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| not_found("action", id))?;
        return Ok(FinishRow {
            status: row.text("status")?,
            run: row.uuid("run_id")?,
            session: row.uuid("session_id")?,
            context: row.i64("context_id")?,
            lane: row.text("lane")?,
            before: row.opt_uuid("before_state_id")?,
            retention_mode: row.text("retention_mode")?,
        });
    }
    // lock the action row alone: locking the run row would serialize every action of a run
    let row = Stmt::<B>::dynamic(&format!(
        "SELECT a.status, a.run_id, a.session_id, a.context_id, a.lane, a.before_state_id \
         FROM actions a WHERE a.action_id = $1{}",
        update_lock::<B>()
    ))
    .uuid(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| not_found("action", id))?;
    let run = row.uuid("run_id")?;
    let retention_mode = stmt!(B, "SELECT retention_mode FROM crawl_runs WHERE run_id = $1")
        .uuid(run)
        .fetch_one(conn)
        .await?
        .text("retention_mode")?;
    Ok(FinishRow {
        status: row.text("status")?,
        run,
        session: row.uuid("session_id")?,
        context: row.i64("context_id")?,
        lane: row.text("lane")?,
        before: row.opt_uuid("before_state_id")?,
        retention_mode,
    })
}

/// Whether `session` still holds a live lease with `fence`, locking the session row.
async fn session_is_live<B: Sql>(
    conn: &mut Conn<B>,
    session: Uuid,
    run: Uuid,
    fence: i64,
) -> Result<bool, StoreError> {
    let live = stmt!(
        B,
        format!(
            "SELECT session_id FROM crawl_sessions WHERE session_id=$1 AND run_id=$2 AND fencing_token=$3 AND lease_expires_at>{} AND status IN ('running','recovering'){}",
            <B::Dialect as Dialect>::now(),
            <B::Dialect as Dialect>::row_lock(RowLock::Update),
        )
    )
    .uuid(session)
    .uuid(run)
    .i64(fence)
    .fetch_optional(conn)
    .await?;
    Ok(live.is_some())
}

impl<B: Sql> Store<B> {
    /// Actions the scheduler may run next (the scheduling rule):
    /// `proposed`, or `reconciled` with resolution `not_applied`, and not held.
    /// `indeterminate` and `applied` are never rescheduled.
    ///
    /// # Errors
    /// Returns an error if the database query fails or an action row cannot be decoded.
    pub async fn eligible_actions(
        &self,
        run: CrawlRunId,
        session: Option<SessionId>,
        limit: u32,
    ) -> Result<Vec<ActionRecord>, StoreError> {
        let _timer = self.query_timer("journal.eligible_actions");
        let rows = stmt!(
            B,
            format!(
                "{ACTION_SELECT}{KEY_COLS} FROM actions a JOIN action_contexts c ON c.context_id = a.context_id \
                 WHERE a.run_id = $1 AND ($2::uuid IS NULL OR a.session_id = $2) AND a.hold = 'none' \
                   AND (a.status = 'proposed' OR (a.status = 'reconciled' AND a.reconcile_resolution = 'not_applied')) \
                 ORDER BY a.proposed_at, a.seq LIMIT $3"
            )
        )
        .uuid(run.0)
        .opt_uuid(session.map(|s| s.0))
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in &rows {
            records.push(record_from_row(self, row).await?);
        }
        Ok(records)
    }
}

#[async_trait]
impl<B: Sql> ActionJournal for Store<B> {
    async fn propose(
        &self,
        run: CrawlRunId,
        session: SessionId,
        p: &ActionProposal,
        v: &SafetyVerdict,
    ) -> Result<ActionId, StoreError> {
        let _timer = self.query_timer("journal.propose");
        let id = ActionId::new();
        let fidelity = p.action.fidelity();
        let mut tx = self.begin_write().await?;
        let (tenant, zdr) = Store::<B>::privacy_scope_tx(tx.conn(), run).await?;
        if zdr {
            self.ephemeral_put(tenant, run, i64::MIN + 1, &format!("_strategy:{id}"), p.strategy)
                .await?;
        }
        // the decision row precedes the action row; `action_id` is not an FK for that reason
        write_decision::<B>(tx.conn(), run, session, Some(id.0), v, &p.summary).await?;
        let ctx = ensure_context(self, tx.conn(), run, &p.key, v.decision == SafetyDecision::Deny).await?;
        let seq = bump_action_seq::<B>(tx.conn(), run, session).await?;
        // ZDR stores only hashes; runtime strategy names stay in the expiring sideband.
        let params = serde_json::json!({ "kind": p.key.action_kind.as_str(), "strategy": p.strategy });
        let params = if zdr {
            super::event::metadata_digest(&params)?
        } else {
            params
        };
        let strategy = if zdr {
            std::borrow::Cow::Owned(Digest::of("crawlx/zdr-strategy/v1", p.strategy.as_bytes()).to_hex())
        } else {
            std::borrow::Cow::Borrowed(p.strategy)
        };
        let trace = crawlx_telemetry::current_trace_id().map(|t| t.to_string());
        let mut insert = stmt!(B, action_insert_sql::<B>())
            .uuid(id.0)
            .uuid(run.0)
            .uuid(session.0)
            .i64(seq)
            .i64(ctx)
            .text(p.key.action_kind.as_str())
            .json(&params)
            .text(&strategy)
            .i32(conv::<u32, i32>(p.strategy_version, "strategy_version")?)
            .i64(conv::<u64, i64>(p.epoch.navigation_seq, "navigation_seq")?)
            .i64(conv::<u64, i64>(p.epoch.document_seq, "document_seq")?)
            .i64(conv::<u64, i64>(p.epoch.mutation_seq, "mutation_seq")?)
            .text(fidelity.as_str())
            .text(fidelity.lane().as_str())
            .uuid(v.decision_id.0)
            .opt_uuid(p.model_decision.map(|m| m.0))
            .text(hold_for(v))
            .opt_text(trace.as_deref());
        if B::KIND == BackendKind::Sqlite {
            insert = insert.i64(B::next_fence(tx.conn(), FenceSeq::ActionDatasetPage).await?);
        }
        insert.execute(tx.conn()).await?;
        if let Some(approval) = v.approval {
            let (_, zdr) = Store::<B>::privacy_scope_tx(tx.conn(), run).await?;
            let summary = serde_json::json!({
                "role": p.key.principal.0,
                "route_template": p.key.route_template.0,
                "action_kind": p.key.action_kind.as_str(),
                "resource_context": p.key.resource_context.as_str(),
                "input_class": p.key.input_class.0,
            });
            let summary = if zdr {
                super::event::metadata_digest(&summary)?
            } else {
                summary
            };
            stmt!(
                B,
                format!(
                    "INSERT INTO approvals (approval_id, run_id, action_id, safety_decision_id, risk_class, summary, expires_at) \
                     VALUES ($1, $2, $3, $4, $5::text::risk_class, $6, {}) {}",
                    <B::Dialect as Dialect>::add_hours(<B::Dialect as Dialect>::now(), "$7"),
                    <B::Dialect as Dialect>::upsert_do_nothing(&["approval_id"]),
                )
            )
            .uuid(approval.0)
            .uuid(run.0)
            .uuid(id.0)
            .uuid(v.decision_id.0)
            .text(v.risk_class.as_str())
            .json(&summary)
            .i32(APPROVAL_TTL_HOURS)
            .execute(tx.conn())
            .await?;
        }
        tx.commit().await?;
        Ok(id)
    }

    async fn intend(
        &self,
        id: ActionId,
        session: SessionId,
        epoch: ObservationEpoch,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("journal.intend");
        let mut tx = self.begin_write().await?;
        if B::KIND == BackendKind::Postgres {
            Stmt::<B>::dynamic("SET LOCAL synchronous_commit = on")
                .execute(tx.conn())
                .await?;
        }
        let row = lock_action_for_intent::<B>(tx.conn(), id).await?;
        if row.session != session.0 {
            return Err(StoreError::Conflict(format!(
                "action {id} belongs to another session"
            )));
        }
        if !matches!(row.session_status.as_str(), "running" | "recovering") {
            return Err(StoreError::LeaseLost);
        }
        if row.hold != "none" {
            return Err(StoreError::Conflict(format!("action {id} is held: {}", row.hold)));
        }
        let status: ActionStatus = parse_label(&row.status)?;
        let next_attempt = match (status, row.resolution.as_deref()) {
            (ActionStatus::Proposed, _) => row.attempt,
            (ActionStatus::Reconciled, Some("not_applied")) => row.attempt + 1,
            _ => {
                return Err(StoreError::IllegalTransition {
                    from: status.as_str().to_owned(),
                    to: "intended".to_owned(),
                })
            }
        };
        let navigation = conv::<u64, i64>(epoch.navigation_seq, "navigation_seq")?;
        let document = conv::<u64, i64>(epoch.document_seq, "document_seq")?;
        let mutation = conv::<u64, i64>(epoch.mutation_seq, "mutation_seq")?;
        let before = stmt!(
            B,
            "SELECT state_id FROM states WHERE session_id = $1 AND (epoch_navigation, epoch_document, epoch_mutation) <= ($2, $3, $4) \
             ORDER BY epoch_navigation DESC, epoch_document DESC, epoch_mutation DESC, observed_at DESC LIMIT 1"
        )
        .uuid(session.0)
        .i64(navigation)
        .i64(document)
        .i64(mutation)
        .fetch_optional(tx.conn())
        .await?
        .map(|row| row.uuid("state_id"))
        .transpose()?;
        stmt!(
            B,
            format!(
                "UPDATE actions SET status = 'intended', attempt = $2, intended_at = {}, finished_at = NULL, before_state_id = $3, \
                   epoch_navigation = $4, epoch_document = $5, epoch_mutation = $6 WHERE action_id = $1",
                <B::Dialect as Dialect>::now()
            )
        )
        .uuid(id.0)
        .i16(next_attempt)
        .opt_uuid(before)
        .i64(navigation)
        .i64(document)
        .i64(mutation)
        .execute(tx.conn())
        .await?;
        stmt!(
            B,
            "UPDATE action_contexts SET attempts = attempts + 1 WHERE context_id = $1"
        )
        .i64(row.context)
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }

    // T2. Every statement is preceded by a `chaos` failpoint (see
    // `crate::chaos::T2_FAILPOINTS`); a fired failpoint drops `tx`, which rolls back.
    async fn finish(&self, id: ActionId, outcome: OutcomeRecord) -> Result<(), StoreError> {
        self.finish_with_accepted(id, outcome, 0, Vec::new(), Vec::new(), Vec::new())
            .await
    }

    async fn dataset_page(&self, id: ActionId) -> Result<i64, StoreError> {
        let ordinal = stmt!(B, "SELECT dataset_page FROM actions WHERE action_id=$1")
            .uuid(id.0)
            .fetch_optional_pool(&self.pool)
            .await?
            .ok_or_else(|| not_found("action", id))?
            .i64("dataset_page")?;
        crate::dataset::action_page(ordinal)
    }

    async fn finish_with_accepted(
        &self,
        id: ActionId,
        outcome: OutcomeRecord,
        session_fence: i64,
        accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
        state_deltas: Vec<crawlx_core::dataset::KvCasV1>,
        outbox: Vec<crawlx_core::dataset::DeliveryBatchV1>,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("journal.finish");
        let mut tx = self.begin_write().await?;
        chaos::fail("t2.select_action")?;
        let row = lock_action_for_finish::<B>(tx.conn(), id).await?;
        let status: ActionStatus = parse_label(&row.status)?;
        if !matches!(
            outcome.status,
            ActionStatus::Succeeded | ActionStatus::Failed | ActionStatus::Unknown
        ) || !status.can_transition_to(outcome.status)
        {
            return Err(StoreError::IllegalTransition {
                from: status.as_str().to_owned(),
                to: outcome.status.as_str().to_owned(),
            });
        }
        let run = CrawlRunId(row.run);
        let session = SessionId(row.session);
        let ctx = row.context;
        if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            if outcome.status != ActionStatus::Succeeded || session_fence <= 0 {
                return Err(StoreError::LeaseLost);
            }
            if !session_is_live::<B>(tx.conn(), session.0, run.0, session_fence).await? {
                return Err(StoreError::LeaseLost);
            }
            crate::dataset::apply_action::<B>(self, tx.conn(), run, id, &accepted, &state_deltas, &outbox)
                .await?;
        }
        // The lane is derived once from the executor's receipt; the proposal's
        // fidelity is only a plan. An outcome without a receipt keeps the proposed lane.
        let proposed_lane: TrustLane = parse_label(&row.lane)?;
        let receipt_fidelity = outcome.receipt.as_ref().map(|r| r.fidelity);
        let lane = receipt_fidelity.map_or(proposed_lane, crawlx_core::traffic::Fidelity::lane);
        let zdr = row.retention_mode == "zdr";
        let before = row.before;
        let outcome_payload = serde_json::json!({
            "status": outcome.status.as_str(),
            "error": outcome.error,
            "receipt": outcome.receipt,
            "settle": outcome.settle,
        });
        let outcome_payload = if zdr {
            super::event::metadata_digest(&outcome_payload)?
        } else {
            outcome_payload
        };

        chaos::fail("t2.update_action")?;
        stmt!(
            B,
            "UPDATE actions SET status = $2::text::action_status, finished_at = $3, outcome = $4, \
               fidelity = COALESCE($5::text::action_fidelity, fidelity), lane = $6::text::trust_lane WHERE action_id = $1"
        )
        .uuid(id.0)
        .text(outcome.status.as_str())
        .ts(outcome.finished_at)
        .json(&outcome_payload)
        .opt_text(receipt_fidelity.map(|f| f.as_str()))
        .text(lane.as_str())
        .execute(tx.conn())
        .await?;

        let epoch_id = outcome.receipt.as_ref().map(|r| r.network_epoch);
        if let Some(receipt) = &outcome.receipt {
            chaos::fail("t2.insert_network_epoch")?;
            let operations: BTreeSet<(&str, &str)> = outcome
                .traffic
                .iter()
                .map(|t| (t.method.as_str(), t.url.split('?').next().unwrap_or("")))
                .collect();
            stmt!(
                B,
                format!(
                    "INSERT INTO network_epochs (epoch_id, run_id, session_id, action_id, lane, started_at, settled_at, request_count, unique_operations, settle_timeout) \
                     VALUES ($1, $2, $3, $4, $5::text::trust_lane, $6, $7, $8, $9, $10) {}",
                    <B::Dialect as Dialect>::upsert_do_nothing(&["epoch_id"])
                )
            )
            .uuid(receipt.network_epoch.0)
            .uuid(run.0)
            .uuid(session.0)
            .uuid(id.0)
            .text(lane.as_str())
            .ts(receipt.started_at)
            .ts(receipt.finished_at)
            .i32(conv::<usize, i32>(outcome.traffic.len(), "request_count")?)
            .i32(conv::<usize, i32>(operations.len(), "unique_operations")?)
            .bool(outcome.settle.as_ref().is_some_and(|s| s.settle_timeout))
            .execute(tx.conn())
            .await?;
        }

        if let Some(after) = &outcome.after_state {
            chaos::fail("t2.insert_state")?;
            insert_state(self, tx.conn(), run, after).await?;
        }

        if !outcome.traffic.is_empty() {
            chaos::fail("t2.insert_traffic")?;
            insert_traffic::<B>(tx.conn(), run, lane, zdr, epoch_id, &outcome).await?;
        }

        if let Some(before) = before {
            chaos::fail("t2.insert_transition")?;
            let default_settle = Default::default();
            let settle = outcome.settle.as_ref().unwrap_or(&default_settle);
            let settle_report = to_json(settle)?;
            stmt!(
                B,
                format!(
                    "INSERT INTO transitions (transition_id, run_id, session_id, before_state_id, action_id, network_epoch_id, after_state_id, lane, settle_report) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::trust_lane, $9) {}",
                    <B::Dialect as Dialect>::upsert_do_nothing(&["action_id"])
                )
            )
            .uuid(TransitionId::new().0)
            .uuid(run.0)
            .uuid(session.0)
            .uuid(before)
            .uuid(id.0)
            .opt_uuid(epoch_id.map(|e| e.0))
            .opt_uuid(outcome.after_state.as_ref().map(|s| s.id.0))
            .text(lane.as_str())
            .json(&settle_report)
            .execute(tx.conn())
            .await?;
        }

        let (ok, bad, unknown) = match outcome.status {
            ActionStatus::Succeeded => (1, 0, 0),
            ActionStatus::Failed => (0, 1, 0),
            _ => (0, 0, 1),
        };
        chaos::fail("t2.update_action_context")?;
        stmt!(
            B,
            "UPDATE action_contexts SET succeeded = succeeded + $2, succeeded_trusted = succeeded_trusted + $3, failed = failed + $4, \
               unknown = unknown + $5, first_exercised_at = COALESCE(first_exercised_at, $6), last_exercised_at = $6, last_action_id = $7 \
             WHERE context_id = $1"
        )
        .i64(ctx)
        .i32(ok)
        .i32(if lane == TrustLane::TrustedUi { ok } else { 0 })
        .i32(bad)
        .i32(unknown)
        .ts(outcome.finished_at)
        .uuid(id.0)
        .execute(tx.conn())
        .await?;

        chaos::fail("t2.append_event")?;
        append_event(
            self,
            tx.conn(),
            run,
            "action.finished",
            serde_json::json!({ "action_id": id.0, "session_id": session.0, "status": outcome.status.as_str(), "lane": lane.as_str() }),
        )
        .await?;
        chaos::fail("t2.commit")?;
        chaos::pause("t2.commit").await;
        tx.commit().await
    }

    async fn mark_unknown(&self, expired_before: Timestamp) -> Result<Vec<ActionId>, StoreError> {
        let _timer = self.query_timer("journal.mark_unknown");
        let mut tx = self.begin_write().await?;
        let mut pairs: Vec<(Uuid, i64)> = Vec::new();
        if B::KIND == BackendKind::Postgres {
            let rows = stmt!(
                B,
                "UPDATE actions a SET status = 'unknown', finished_at = now() FROM crawl_sessions s \
                 WHERE a.session_id = s.session_id AND a.status = 'intended' AND s.status IN ('running','recovering') AND s.lease_expires_at < $1 \
                 RETURNING a.action_id, a.context_id"
            )
            .ts(expired_before)
            .fetch_all(tx.conn())
            .await?;
            for r in &rows {
                pairs.push((r.uuid("action_id")?, r.i64("context_id")?));
            }
        } else {
            // the subquery is not a locking read: only the action rows are locked
            let expired = "a.session_id IN (SELECT session_id FROM crawl_sessions WHERE status IN ('running','recovering') AND lease_expires_at < $1)";
            let rows = Stmt::<B>::dynamic(&format!(
                "SELECT a.action_id, a.context_id FROM actions a WHERE a.status = 'intended' AND {expired}{}",
                update_lock::<B>()
            ))
            .ts(expired_before)
            .fetch_all(tx.conn())
            .await?;
            for r in &rows {
                pairs.push((r.uuid("action_id")?, r.i64("context_id")?));
            }
            Stmt::<B>::dynamic(&format!(
                "UPDATE actions SET status = 'unknown', finished_at = {} WHERE status = 'intended' AND {}",
                <B::Dialect as Dialect>::now(),
                expired.replace("a.session_id", "session_id"),
            ))
            .ts(expired_before)
            .execute(tx.conn())
            .await?;
        }
        bump_unknown::<B>(tx.conn(), &pairs).await?;
        tx.commit().await?;
        Ok(pairs.into_iter().map(|(a, _)| ActionId(a)).collect())
    }

    async fn reconcile(&self, id: ActionId, r: Reconciliation) -> Result<(), StoreError> {
        self.reconcile_with_accepted(id, r, 0, Vec::new(), Vec::new(), Vec::new())
            .await
    }

    async fn reconcile_with_accepted(
        &self,
        id: ActionId,
        r: Reconciliation,
        session_fence: i64,
        accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
        state_deltas: Vec<crawlx_core::dataset::KvCasV1>,
        outbox: Vec<crawlx_core::dataset::DeliveryBatchV1>,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("journal.reconcile");
        let mut tx = self.begin_write().await?;
        let row = Stmt::<B>::dynamic(&format!(
            "SELECT status::text AS status, run_id, session_id FROM actions WHERE action_id = $1{}",
            update_lock::<B>()
        ))
        .uuid(id.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or_else(|| not_found("action", id))?;
        let status: ActionStatus = parse_label(&row.text("status")?)?;
        if !status.can_transition_to(ActionStatus::Reconciled) {
            return Err(StoreError::IllegalTransition {
                from: status.as_str().to_owned(),
                to: "reconciled".to_owned(),
            });
        }
        let run = CrawlRunId(row.uuid("run_id")?);
        let session = row.uuid("session_id")?;
        if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            if r.resolution != crawlx_core::counters::ReconcileResolution::Applied || session_fence <= 0 {
                return Err(StoreError::LeaseLost);
            }
            if !session_is_live::<B>(tx.conn(), session, run.0, session_fence).await? {
                return Err(StoreError::LeaseLost);
            }
            crate::dataset::apply_action::<B>(self, tx.conn(), run, id, &accepted, &state_deltas, &outbox)
                .await?;
        }
        let (_, zdr) = Store::<B>::privacy_scope_tx(tx.conn(), run).await?;
        let evidence_metadata = if zdr {
            Some(super::event::metadata_digest(&r.evidence)?)
        } else {
            None
        };
        let evidence = evidence_metadata.as_ref().unwrap_or(&r.evidence);
        if B::KIND == BackendKind::Postgres {
            stmt!(
                B,
                "UPDATE actions SET status = 'reconciled', reconcile_resolution = $2, reconciled_at = $3, \
                   outcome = COALESCE(outcome, '{}'::jsonb) || jsonb_build_object('reconciliation', $4::jsonb) WHERE action_id = $1"
            )
            .uuid(id.0)
            .text(r.resolution.as_str())
            .ts(r.reconciled_at)
            .json(evidence)
            .execute(tx.conn())
            .await?;
        } else {
            // merge the evidence into the stored outcome here; the action row is locked
            let current = stmt!(B, "SELECT outcome FROM actions WHERE action_id = $1")
                .uuid(id.0)
                .fetch_one(tx.conn())
                .await?
                .opt_json("outcome")?;
            let mut merged = match current {
                Some(serde_json::Value::Object(map)) => map,
                _ => serde_json::Map::new(),
            };
            merged.insert("reconciliation".to_owned(), evidence.clone());
            let merged = serde_json::Value::Object(merged);
            stmt!(
                B,
                "UPDATE actions SET status = 'reconciled', reconcile_resolution = $2, reconciled_at = $3, outcome = $4 WHERE action_id = $1"
            )
            .uuid(id.0)
            .text(r.resolution.as_str())
            .ts(r.reconciled_at)
            .json(&merged)
            .execute(tx.conn())
            .await?;
        }
        append_event(
            self,
            tx.conn(),
            run,
            "action.reconciled",
            serde_json::json!({ "action_id": id.0, "session_id": session, "resolution": r.resolution.as_str() }),
        )
        .await?;
        tx.commit().await
    }

    async fn get(&self, id: ActionId) -> Result<ActionRecord, StoreError> {
        let _timer = self.query_timer("journal.get");
        let row = stmt!(
            B,
            format!("{ACTION_SELECT}{KEY_COLS} FROM actions a JOIN action_contexts c ON c.context_id = a.context_id WHERE a.action_id = $1")
        )
        .uuid(id.0)
        .fetch_optional_pool(&self.pool)
        .await?
        .ok_or_else(|| not_found("action", id))?;
        record_from_row(self, &row).await
    }

    async fn list(
        &self,
        run: CrawlRunId,
        status: Option<ActionStatus>,
    ) -> Result<Vec<ActionRecord>, StoreError> {
        let _timer = self.query_timer("journal.list");
        let rows = stmt!(
            B,
            format!(
                "{ACTION_SELECT}{KEY_COLS} FROM actions a JOIN action_contexts c ON c.context_id = a.context_id \
                 WHERE a.run_id = $1 AND ($2::text IS NULL OR a.status::text = $2) ORDER BY a.session_id, a.seq"
            )
        )
        .uuid(run.0)
        .opt_text(status.map(ActionStatus::as_str))
        .fetch_all_pool(&self.pool)
        .await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in &rows {
            records.push(record_from_row(self, row).await?);
        }
        Ok(records)
    }

    async fn outcome_counts(&self, run: CrawlRunId) -> Result<JournalOutcomes, StoreError> {
        let _timer = self.query_timer("journal.outcome_counts");
        // mirrors `JournalOutcomes::tally`: a reconcile resolution is only ever set on a row
        // that went through `unknown`, and survives a `not_applied` re-intent
        let row = stmt!(
            B,
            format!(
                "SELECT {} AS succeeded, \
                        {} AS failed, \
                        {} AS unknown \
                 FROM actions WHERE run_id = $1",
                <B::Dialect as Dialect>::count_where("status = 'succeeded'"),
                <B::Dialect as Dialect>::count_where("status = 'failed'"),
                <B::Dialect as Dialect>::count_where(
                    "status IN ('unknown', 'reconciled') OR reconcile_resolution IS NOT NULL"
                ),
            )
        )
        .uuid(run.0)
        .fetch_one_pool(&self.pool)
        .await?;
        Ok(JournalOutcomes::new(
            conv(row.i64("succeeded")?, "succeeded")?,
            conv(row.i64("failed")?, "failed")?,
            conv(row.i64("unknown")?, "unknown")?,
        ))
    }
}

/// Insert the traffic of one action through the engine's batch path (`UNNEST` on
/// PostgreSQL, chunked `VALUES` elsewhere).
async fn insert_traffic<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    lane: TrustLane,
    zdr: bool,
    receipt_epoch: Option<crawlx_core::NetworkEpochId>,
    outcome: &OutcomeRecord,
) -> Result<(), StoreError> {
    let mut rows = Vec::with_capacity(outcome.traffic.len());
    for t in &outcome.traffic {
        let (epoch, reason) = traffic_attribution(t, receipt_epoch)?;
        // ZDR keeps url_hash, method and status only
        let (url, request_headers, response_headers) = if zdr {
            (None, None, None)
        } else {
            (
                Some(t.url.as_str()),
                Some(to_json(&t.request_headers)?),
                Some(to_json(&t.response_headers)?),
            )
        };
        rows.push(TrafficRow {
            occurred_at: t.started_at,
            epoch: epoch.map(|e| e.0),
            reason: reason.map(crawlx_core::traffic::UnattributedReason::as_str),
            seq: conv::<u64, i32>(t.seq, "traffic seq")?,
            origin: origin_label(t.origin),
            third_party: t.third_party,
            late: t.late,
            method: t.method.as_str(),
            url,
            url_hash: Digest::of("crawlx/traffic-url/v1", t.url.as_bytes()).0.to_vec(),
            status: t.status.map(i32::from),
            request_headers,
            response_headers,
            body: if zdr {
                None
            } else {
                t.response_body.as_ref().map(|a| a.id.0)
            },
            request_body: if zdr {
                None
            } else {
                t.request_body.as_ref().map(|a| a.id.0)
            },
            finished_at: t.finished_at,
        });
    }
    B::insert_traffic(conn, run.0, lane.as_str(), &rows).await
}

/// The epoch a traffic row is attributed to, or the explicit reason it has none
/// (one of the two, never neither, never both). An event with its own
/// `epoch_id` is attributed to it; one with neither epoch nor reason inherits the
/// action's receipt epoch; an explicit reason is final (the receipt epoch does not
/// override it: fetch-plane traffic under a browser action stays unattributed).
///
/// # Errors
/// [`StoreError::Conflict`] when the event has neither an epoch (own or the receipt's)
/// nor an `unattributed_reason`, or carries both an `epoch_id` and a reason.
pub(crate) fn traffic_attribution(
    t: &crawlx_core::traffic::TrafficEvent,
    receipt_epoch: Option<crawlx_core::NetworkEpochId>,
) -> Result<
    (
        Option<crawlx_core::NetworkEpochId>,
        Option<crawlx_core::traffic::UnattributedReason>,
    ),
    StoreError,
> {
    match (t.epoch_id, t.unattributed_reason) {
        (Some(e), None) => Ok((Some(e), None)),
        (Some(_), Some(_)) => Err(StoreError::Conflict(
            "traffic event with both a network epoch and an unattributed reason".to_owned(),
        )),
        (None, Some(r)) => Ok((None, Some(r))),
        (None, None) => receipt_epoch.map(|e| (Some(e), None)).ok_or_else(|| {
            StoreError::Conflict(
                "traffic event without a network epoch and without an unattributed reason".to_owned(),
            )
        }),
    }
}
