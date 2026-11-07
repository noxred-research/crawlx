//! `ActionJournal`: T1 intent, T2 outcome, reaper `unknown`, reconciliation.

use super::event::append_event;
use super::ledger::{ensure_context, key_from_row, KEY_COLS};
use super::safety::write_decision;
use super::state::insert_state;
use crate::chaos;
use crate::codec::{conv, get, origin_label, parse_label, to_json};
use crate::error::{db, not_found};
use crate::pg::Pg;
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
use sqlx::postgres::PgRow;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use uuid::Uuid;

/// How long a pending approval stays valid (24 h).
const APPROVAL_TTL_HOURS: i32 = 24;

const ACTION_SELECT: &str = "SELECT a.action_id, a.run_id, a.session_id, a.seq, a.status::text AS status, a.attempt, a.strategy, a.strategy_version, \
    a.epoch_navigation, a.epoch_document, a.epoch_mutation, a.fidelity::text AS fidelity, a.lane::text AS lane, a.safety_decision_id, \
    a.model_decision_id, a.before_state_id, a.reconcile_resolution, a.proposed_at, a.intended_at, a.finished_at, a.trace_id, ";

async fn record_from_row(pg: &Pg, r: &PgRow) -> Result<ActionRecord, StoreError> {
    let strategy = if get::<bool>(r, "context_zdr")? {
        let tenant = crawlx_core::TenantId(get(r, "context_tenant_id")?);
        let run = CrawlRunId(get(r, "run_id")?);
        let action = ActionId(get(r, "action_id")?);
        pg.ephemeral_get(tenant, run, i64::MIN + 1, &format!("_strategy:{action}"))
            .await?
    } else {
        get(r, "strategy")?
    };
    Ok(ActionRecord {
        id: ActionId(get(r, "action_id")?),
        run: CrawlRunId(get(r, "run_id")?),
        session: SessionId(get(r, "session_id")?),
        seq: conv(get::<i64>(r, "seq")?, "seq")?,
        key: key_from_row(pg, r).await?,
        status: parse_label(&get::<String>(r, "status")?)?,
        attempt: conv(get::<i16>(r, "attempt")?, "attempt")?,
        strategy,
        strategy_version: conv(get::<i32>(r, "strategy_version")?, "strategy_version")?,
        epoch: ObservationEpoch {
            navigation_seq: conv(get::<i64>(r, "epoch_navigation")?, "epoch_navigation")?,
            document_seq: conv(get::<i64>(r, "epoch_document")?, "epoch_document")?,
            mutation_seq: conv(get::<i64>(r, "epoch_mutation")?, "epoch_mutation")?,
        },
        lane: Some(parse_label(&get::<String>(r, "lane")?)?),
        fidelity: Some(parse_label(&get::<String>(r, "fidelity")?)?),
        safety_decision: SafetyDecisionId(get(r, "safety_decision_id")?),
        model_decision: get::<Option<Uuid>>(r, "model_decision_id")?.map(ModelDecisionId),
        before_state: get::<Option<Uuid>>(r, "before_state_id")?.map(StateId),
        reconcile_resolution: get::<Option<String>>(r, "reconcile_resolution")?
            .map(|s| parse_label(&s))
            .transpose()?,
        proposed_at: get(r, "proposed_at")?,
        intended_at: get(r, "intended_at")?,
        finished_at: get(r, "finished_at")?,
        trace_id: get::<Option<String>>(r, "trace_id")?
            .map(|s| TraceId::from_str(&s).map_err(|e| StoreError::Serialization(e.to_string())))
            .transpose()?,
    })
}

async fn bump_unknown(conn: &mut PgConnection, rows: &[(Uuid, i64)]) -> Result<(), StoreError> {
    let mut per_ctx: BTreeMap<i64, i32> = BTreeMap::new();
    for (_, ctx) in rows {
        *per_ctx.entry(*ctx).or_insert(0) += 1;
    }
    for (ctx, n) in per_ctx {
        sqlx::query("UPDATE action_contexts SET unknown = unknown + $2 WHERE context_id = $1")
            .bind(ctx)
            .bind(n)
            .execute(&mut *conn)
            .await
            .map_err(db)?;
    }
    Ok(())
}

/// `intended → unknown` for every `intended` action of `session_ids`; bumps the ledger.
/// `finished_at` is the instant of the flip: when the outcome was declared unknown
/// (the trail verifier requires it on every final-status row).
pub(crate) async fn flip_intended_to_unknown(
    conn: &mut PgConnection,
    session_ids: &[Uuid],
) -> Result<Vec<ActionId>, StoreError> {
    if session_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query("UPDATE actions SET status = 'unknown', finished_at = now() WHERE session_id = ANY($1) AND status = 'intended' RETURNING action_id, context_id")
        .bind(session_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
    let pairs = rows
        .iter()
        .map(|r| Ok((get::<Uuid>(r, "action_id")?, get::<i64>(r, "context_id")?)))
        .collect::<Result<Vec<_>, StoreError>>()?;
    bump_unknown(conn, &pairs).await?;
    Ok(pairs.into_iter().map(|(a, _)| ActionId(a)).collect())
}

fn hold_for(v: &SafetyVerdict) -> &'static str {
    match v.decision {
        SafetyDecision::Allow => "none",
        SafetyDecision::Deny => "denied",
        SafetyDecision::ApprovalRequired => "awaiting_approval",
    }
}

impl Pg {
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
        let sql = format!(
            "{ACTION_SELECT}{KEY_COLS} FROM actions a JOIN action_contexts c ON c.context_id = a.context_id \
             WHERE a.run_id = $1 AND ($2::uuid IS NULL OR a.session_id = $2) AND a.hold = 'none' \
               AND (a.status = 'proposed' OR (a.status = 'reconciled' AND a.reconcile_resolution = 'not_applied')) \
             ORDER BY a.proposed_at, a.seq LIMIT $3"
        );
        let rows = sqlx::query(&sql)
            .bind(run.0)
            .bind(session.map(|s| s.0))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        let mut records = Vec::with_capacity(rows.len());
        for row in &rows {
            records.push(record_from_row(self, row).await?);
        }
        Ok(records)
    }
}

#[async_trait]
impl ActionJournal for Pg {
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
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, zdr) = Pg::privacy_scope_tx(&mut tx, run).await?;
        if zdr {
            self.ephemeral_put(tenant, run, i64::MIN + 1, &format!("_strategy:{id}"), p.strategy)
                .await?;
        }
        // the decision row precedes the action row; `action_id` is not an FK for that reason
        write_decision(&mut tx, run, session, Some(id.0), v, &p.summary).await?;
        let ctx = ensure_context(self, &mut tx, run, &p.key, v.decision == SafetyDecision::Deny).await?;
        let seq: Option<i64> =
            sqlx::query_scalar("UPDATE crawl_sessions SET action_seq = action_seq + 1 WHERE session_id = $1 AND run_id = $2 RETURNING action_seq")
                .bind(session.0)
                .bind(run.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let seq = seq.ok_or_else(|| not_found("crawl_session", session))?;
        // ZDR stores only hashes; runtime strategy names stay in the expiring sideband.
        let params = serde_json::json!({ "kind": p.key.action_kind.as_str(), "strategy": p.strategy });
        sqlx::query(
            "INSERT INTO actions (action_id, run_id, session_id, seq, context_id, action_kind, params, strategy, strategy_version, \
               epoch_navigation, epoch_document, epoch_mutation, fidelity, lane, safety_decision_id, model_decision_id, hold, trace_id) \
             VALUES ($1, $2, $3, $4, $5, $6::text::action_kind, $7, $8, $9, $10, $11, $12, $13::text::action_fidelity, $14::text::trust_lane, $15, $16, $17, $18)",
        )
        .bind(id.0)
        .bind(run.0)
        .bind(session.0)
        .bind(seq)
        .bind(ctx)
        .bind(p.key.action_kind.as_str())
        .bind(if zdr { super::event::metadata_digest(&params)? } else { params })
        .bind(if zdr {
            std::borrow::Cow::Owned(Digest::of("crawlx/zdr-strategy/v1", p.strategy.as_bytes()).to_hex())
        } else {
            std::borrow::Cow::Borrowed(p.strategy)
        })
        .bind(conv::<u32, i32>(p.strategy_version, "strategy_version")?)
        .bind(conv::<u64, i64>(p.epoch.navigation_seq, "navigation_seq")?)
        .bind(conv::<u64, i64>(p.epoch.document_seq, "document_seq")?)
        .bind(conv::<u64, i64>(p.epoch.mutation_seq, "mutation_seq")?)
        .bind(fidelity.as_str())
        .bind(fidelity.lane().as_str())
        .bind(v.decision_id.0)
        .bind(p.model_decision.map(|m| m.0))
        .bind(hold_for(v))
        .bind(crawlx_telemetry::current_trace_id().map(|t| t.to_string()))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if let Some(approval) = v.approval {
            let (_, zdr) = Pg::privacy_scope_tx(&mut tx, run).await?;
            let summary = serde_json::json!({
                "role": p.key.principal.0,
                "route_template": p.key.route_template.0,
                "action_kind": p.key.action_kind.as_str(),
                "resource_context": p.key.resource_context.as_str(),
                "input_class": p.key.input_class.0,
            });
            sqlx::query(
                "INSERT INTO approvals (approval_id, run_id, action_id, safety_decision_id, risk_class, summary, expires_at) \
                 VALUES ($1, $2, $3, $4, $5::text::risk_class, $6, now() + make_interval(hours => $7)) ON CONFLICT (approval_id) DO NOTHING",
            )
            .bind(approval.0)
            .bind(run.0)
            .bind(id.0)
            .bind(v.decision_id.0)
            .bind(v.risk_class.as_str())
            .bind(if zdr { super::event::metadata_digest(&summary)? } else { summary })
            .bind(APPROVAL_TTL_HOURS)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(id)
    }

    async fn intend(
        &self,
        id: ActionId,
        session: SessionId,
        epoch: ObservationEpoch,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("journal.intend");
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let row = sqlx::query(
            "SELECT a.status::text AS status, a.attempt, a.hold, a.session_id, a.context_id, a.reconcile_resolution, s.status AS session_status \
             FROM actions a JOIN crawl_sessions s ON s.session_id = a.session_id WHERE a.action_id = $1 FOR UPDATE OF a",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("action", id))?;
        if get::<Uuid>(&row, "session_id")? != session.0 {
            return Err(StoreError::Conflict(format!(
                "action {id} belongs to another session"
            )));
        }
        if !matches!(
            get::<String>(&row, "session_status")?.as_str(),
            "running" | "recovering"
        ) {
            return Err(StoreError::LeaseLost);
        }
        let hold: String = get(&row, "hold")?;
        if hold != "none" {
            return Err(StoreError::Conflict(format!("action {id} is held: {hold}")));
        }
        let status: ActionStatus = parse_label(&get::<String>(&row, "status")?)?;
        let attempt: i16 = get(&row, "attempt")?;
        let resolution: Option<String> = get(&row, "reconcile_resolution")?;
        let next_attempt = match (status, resolution.as_deref()) {
            (ActionStatus::Proposed, _) => attempt,
            (ActionStatus::Reconciled, Some("not_applied")) => attempt + 1,
            _ => {
                return Err(StoreError::IllegalTransition {
                    from: status.as_str().to_owned(),
                    to: "intended".to_owned(),
                })
            }
        };
        let before: Option<Uuid> = sqlx::query_scalar(
            "SELECT state_id FROM states WHERE session_id = $1 AND (epoch_navigation, epoch_document, epoch_mutation) <= ($2, $3, $4) \
             ORDER BY epoch_navigation DESC, epoch_document DESC, epoch_mutation DESC, observed_at DESC LIMIT 1",
        )
        .bind(session.0)
        .bind(conv::<u64, i64>(epoch.navigation_seq, "navigation_seq")?)
        .bind(conv::<u64, i64>(epoch.document_seq, "document_seq")?)
        .bind(conv::<u64, i64>(epoch.mutation_seq, "mutation_seq")?)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query(
            "UPDATE actions SET status = 'intended', attempt = $2, intended_at = now(), finished_at = NULL, before_state_id = $3, \
               epoch_navigation = $4, epoch_document = $5, epoch_mutation = $6 WHERE action_id = $1",
        )
        .bind(id.0)
        .bind(next_attempt)
        .bind(before)
        .bind(conv::<u64, i64>(epoch.navigation_seq, "navigation_seq")?)
        .bind(conv::<u64, i64>(epoch.document_seq, "document_seq")?)
        .bind(conv::<u64, i64>(epoch.mutation_seq, "mutation_seq")?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query("UPDATE action_contexts SET attempts = attempts + 1 WHERE context_id = $1")
            .bind(get::<i64>(&row, "context_id")?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    // T2. Every statement is preceded by a `chaos` failpoint (see
    // `crate::chaos::T2_FAILPOINTS`); a fired failpoint drops `tx`, which rolls back.
    async fn finish(&self, id: ActionId, outcome: OutcomeRecord) -> Result<(), StoreError> {
        self.finish_with_accepted(id, outcome, 0, Vec::new(), Vec::new(), Vec::new())
            .await
    }

    async fn dataset_page(&self, id: ActionId) -> Result<i64, StoreError> {
        let ordinal: i64 = sqlx::query_scalar("SELECT dataset_page FROM actions WHERE action_id=$1")
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("action", id))?;
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
        let mut tx = self.pool.begin().await.map_err(db)?;
        chaos::fail("t2.select_action")?;
        let row = sqlx::query(
            "SELECT a.status::text AS status, a.run_id, a.session_id, a.context_id, a.lane::text AS lane, a.before_state_id, r.retention_mode::text AS retention_mode \
             FROM actions a JOIN crawl_runs r ON r.run_id = a.run_id WHERE a.action_id = $1 FOR UPDATE OF a",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("action", id))?;
        let status: ActionStatus = parse_label(&get::<String>(&row, "status")?)?;
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
        let run = CrawlRunId(get(&row, "run_id")?);
        let session = SessionId(get(&row, "session_id")?);
        let ctx: i64 = get(&row, "context_id")?;
        if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            if outcome.status != ActionStatus::Succeeded || session_fence <= 0 {
                return Err(StoreError::LeaseLost);
            }
            let live: Option<Uuid> = sqlx::query_scalar("SELECT session_id FROM crawl_sessions WHERE session_id=$1 AND run_id=$2 AND fencing_token=$3 AND lease_expires_at>now() AND status IN ('running','recovering') FOR UPDATE")
                .bind(session.0).bind(run.0).bind(session_fence).fetch_optional(&mut *tx).await.map_err(db)?;
            if live.is_none() {
                return Err(StoreError::LeaseLost);
            }
            crate::dataset::apply_pg_action(self, &mut tx, run, id, &accepted, &state_deltas, &outbox)
                .await?;
        }
        // The lane is derived once from the executor's receipt; the proposal's
        // fidelity is only a plan. An outcome without a receipt keeps the proposed lane.
        let proposed_lane: TrustLane = parse_label(&get::<String>(&row, "lane")?)?;
        let receipt_fidelity = outcome.receipt.as_ref().map(|r| r.fidelity);
        let lane = receipt_fidelity.map_or(proposed_lane, crawlx_core::traffic::Fidelity::lane);
        let zdr = get::<String>(&row, "retention_mode")? == "zdr";
        let before: Option<Uuid> = get(&row, "before_state_id")?;
        let outcome_payload = serde_json::json!({
            "status": outcome.status.as_str(),
            "error": outcome.error,
            "receipt": outcome.receipt,
            "settle": outcome.settle,
        });

        chaos::fail("t2.update_action")?;
        sqlx::query(
            "UPDATE actions SET status = $2::text::action_status, finished_at = $3, outcome = $4, \
               fidelity = COALESCE($5::text::action_fidelity, fidelity), lane = $6::text::trust_lane WHERE action_id = $1",
        )
        .bind(id.0)
        .bind(outcome.status.as_str())
        .bind(outcome.finished_at)
        .bind(if zdr { super::event::metadata_digest(&outcome_payload)? } else { outcome_payload })
        .bind(receipt_fidelity.map(|f| f.as_str()))
        .bind(lane.as_str())
        .execute(&mut *tx)
        .await
        .map_err(db)?;

        let epoch_id = outcome.receipt.as_ref().map(|r| r.network_epoch);
        if let Some(receipt) = &outcome.receipt {
            chaos::fail("t2.insert_network_epoch")?;
            let operations: BTreeSet<(&str, &str)> = outcome
                .traffic
                .iter()
                .map(|t| (t.method.as_str(), t.url.split('?').next().unwrap_or("")))
                .collect();
            sqlx::query(
                "INSERT INTO network_epochs (epoch_id, run_id, session_id, action_id, lane, started_at, settled_at, request_count, unique_operations, settle_timeout) \
                 VALUES ($1, $2, $3, $4, $5::text::trust_lane, $6, $7, $8, $9, $10) ON CONFLICT (epoch_id) DO NOTHING",
            )
            .bind(receipt.network_epoch.0)
            .bind(run.0)
            .bind(session.0)
            .bind(id.0)
            .bind(lane.as_str())
            .bind(receipt.started_at)
            .bind(receipt.finished_at)
            .bind(conv::<usize, i32>(outcome.traffic.len(), "request_count")?)
            .bind(conv::<usize, i32>(operations.len(), "unique_operations")?)
            .bind(outcome.settle.as_ref().is_some_and(|s| s.settle_timeout))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }

        if let Some(after) = &outcome.after_state {
            chaos::fail("t2.insert_state")?;
            insert_state(self, &mut tx, run, after).await?;
        }

        if !outcome.traffic.is_empty() {
            chaos::fail("t2.insert_traffic")?;
            insert_traffic(&mut tx, run, lane, zdr, epoch_id, &outcome).await?;
        }

        if let Some(before) = before {
            chaos::fail("t2.insert_transition")?;
            let default_settle = Default::default();
            let settle = outcome.settle.as_ref().unwrap_or(&default_settle);
            sqlx::query(
                "INSERT INTO transitions (transition_id, run_id, session_id, before_state_id, action_id, network_epoch_id, after_state_id, lane, settle_report) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::trust_lane, $9) ON CONFLICT (action_id) DO NOTHING",
            )
            .bind(TransitionId::new().0)
            .bind(run.0)
            .bind(session.0)
            .bind(before)
            .bind(id.0)
            .bind(epoch_id.map(|e| e.0))
            .bind(outcome.after_state.as_ref().map(|s| s.id.0))
            .bind(lane.as_str())
            .bind(to_json(settle)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }

        let (ok, bad, unknown) = match outcome.status {
            ActionStatus::Succeeded => (1, 0, 0),
            ActionStatus::Failed => (0, 1, 0),
            _ => (0, 0, 1),
        };
        chaos::fail("t2.update_action_context")?;
        sqlx::query(
            "UPDATE action_contexts SET succeeded = succeeded + $2, succeeded_trusted = succeeded_trusted + $3, failed = failed + $4, \
               unknown = unknown + $5, first_exercised_at = COALESCE(first_exercised_at, $6), last_exercised_at = $6, last_action_id = $7 \
             WHERE context_id = $1",
        )
        .bind(ctx)
        .bind(ok)
        .bind(if lane == TrustLane::TrustedUi { ok } else { 0 })
        .bind(bad)
        .bind(unknown)
        .bind(outcome.finished_at)
        .bind(id.0)
        .execute(&mut *tx)
        .await
        .map_err(db)?;

        chaos::fail("t2.append_event")?;
        append_event(
            self,
            &mut tx,
            run,
            "action.finished",
            serde_json::json!({ "action_id": id.0, "session_id": session.0, "status": outcome.status.as_str(), "lane": lane.as_str() }),
        )
        .await?;
        chaos::fail("t2.commit")?;
        chaos::pause("t2.commit").await;
        tx.commit().await.map_err(db)
    }

    async fn mark_unknown(&self, expired_before: Timestamp) -> Result<Vec<ActionId>, StoreError> {
        let _timer = self.query_timer("journal.mark_unknown");
        let mut tx = self.pool.begin().await.map_err(db)?;
        let rows = sqlx::query(
            "UPDATE actions a SET status = 'unknown', finished_at = now() FROM crawl_sessions s \
             WHERE a.session_id = s.session_id AND a.status = 'intended' AND s.status IN ('running','recovering') AND s.lease_expires_at < $1 \
             RETURNING a.action_id, a.context_id",
        )
        .bind(expired_before)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let pairs = rows
            .iter()
            .map(|r| Ok((get::<Uuid>(r, "action_id")?, get::<i64>(r, "context_id")?)))
            .collect::<Result<Vec<_>, StoreError>>()?;
        bump_unknown(&mut tx, &pairs).await?;
        tx.commit().await.map_err(db)?;
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
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row = sqlx::query(
            "SELECT status::text AS status, run_id, session_id FROM actions WHERE action_id = $1 FOR UPDATE",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("action", id))?;
        let status: ActionStatus = parse_label(&get::<String>(&row, "status")?)?;
        if !status.can_transition_to(ActionStatus::Reconciled) {
            return Err(StoreError::IllegalTransition {
                from: status.as_str().to_owned(),
                to: "reconciled".to_owned(),
            });
        }
        let run = CrawlRunId(get(&row, "run_id")?);
        if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            if r.resolution != crawlx_core::counters::ReconcileResolution::Applied || session_fence <= 0 {
                return Err(StoreError::LeaseLost);
            }
            let live: Option<Uuid> = sqlx::query_scalar("SELECT session_id FROM crawl_sessions WHERE session_id=$1 AND run_id=$2 AND fencing_token=$3 AND lease_expires_at>now() AND status IN ('running','recovering') FOR UPDATE")
                .bind(get::<Uuid>(&row,"session_id")?).bind(run.0).bind(session_fence).fetch_optional(&mut *tx).await.map_err(db)?;
            if live.is_none() {
                return Err(StoreError::LeaseLost);
            }
            crate::dataset::apply_pg_action(self, &mut tx, run, id, &accepted, &state_deltas, &outbox)
                .await?;
        }
        let (_, zdr) = Pg::privacy_scope_tx(&mut tx, run).await?;
        let evidence_metadata = if zdr {
            Some(super::event::metadata_digest(&r.evidence)?)
        } else {
            None
        };
        sqlx::query(
            "UPDATE actions SET status = 'reconciled', reconcile_resolution = $2, reconciled_at = $3, \
               outcome = COALESCE(outcome, '{}'::jsonb) || jsonb_build_object('reconciliation', $4::jsonb) WHERE action_id = $1",
        )
        .bind(id.0)
        .bind(r.resolution.as_str())
        .bind(r.reconciled_at)
        .bind(evidence_metadata.as_ref().unwrap_or(&r.evidence))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        append_event(
            self,
            &mut tx,
            run,
            "action.reconciled",
            serde_json::json!({ "action_id": id.0, "session_id": get::<Uuid>(&row, "session_id")?, "resolution": r.resolution.as_str() }),
        )
        .await?;
        tx.commit().await.map_err(db)
    }

    async fn get(&self, id: ActionId) -> Result<ActionRecord, StoreError> {
        let _timer = self.query_timer("journal.get");
        let sql = format!("{ACTION_SELECT}{KEY_COLS} FROM actions a JOIN action_contexts c ON c.context_id = a.context_id WHERE a.action_id = $1");
        let row = sqlx::query(&sql)
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("action", id))?;
        record_from_row(self, &row).await
    }

    async fn list(
        &self,
        run: CrawlRunId,
        status: Option<ActionStatus>,
    ) -> Result<Vec<ActionRecord>, StoreError> {
        let _timer = self.query_timer("journal.list");
        let sql = format!(
            "{ACTION_SELECT}{KEY_COLS} FROM actions a JOIN action_contexts c ON c.context_id = a.context_id \
             WHERE a.run_id = $1 AND ($2::text IS NULL OR a.status::text = $2) ORDER BY a.session_id, a.seq"
        );
        let rows = sqlx::query(&sql)
            .bind(run.0)
            .bind(status.map(ActionStatus::as_str))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
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
        let row = sqlx::query(
            "SELECT count(*) FILTER (WHERE status = 'succeeded') AS succeeded, \
                    count(*) FILTER (WHERE status = 'failed') AS failed, \
                    count(*) FILTER (WHERE status IN ('unknown', 'reconciled') OR reconcile_resolution IS NOT NULL) AS unknown \
             FROM actions WHERE run_id = $1",
        )
        .bind(run.0)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        Ok(JournalOutcomes::new(
            conv(get::<i64>(&row, "succeeded")?, "succeeded")?,
            conv(get::<i64>(&row, "failed")?, "failed")?,
            conv(get::<i64>(&row, "unknown")?, "unknown")?,
        ))
    }
}

/// Batch-insert the traffic of one action via `UNNEST` (a `COPY`-style batch).
async fn insert_traffic(
    conn: &mut PgConnection,
    run: CrawlRunId,
    lane: TrustLane,
    zdr: bool,
    receipt_epoch: Option<crawlx_core::NetworkEpochId>,
    outcome: &OutcomeRecord,
) -> Result<(), StoreError> {
    let n = outcome.traffic.len();
    let mut occurred = Vec::with_capacity(n);
    let mut epochs: Vec<Option<Uuid>> = Vec::with_capacity(n);
    let mut reasons: Vec<Option<&str>> = Vec::with_capacity(n);
    let mut seqs = Vec::with_capacity(n);
    let mut origins = Vec::with_capacity(n);
    let mut third = Vec::with_capacity(n);
    let mut late = Vec::with_capacity(n);
    let mut methods = Vec::with_capacity(n);
    let mut urls: Vec<Option<&str>> = Vec::with_capacity(n);
    let mut hashes: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut statuses: Vec<Option<i32>> = Vec::with_capacity(n);
    let mut req_h: Vec<Option<serde_json::Value>> = Vec::with_capacity(n);
    let mut resp_h: Vec<Option<serde_json::Value>> = Vec::with_capacity(n);
    let mut bodies: Vec<Option<Uuid>> = Vec::with_capacity(n);
    let mut req_bodies: Vec<Option<Uuid>> = Vec::with_capacity(n);
    let mut finished: Vec<Option<Timestamp>> = Vec::with_capacity(n);
    for t in &outcome.traffic {
        let (epoch, reason) = traffic_attribution(t, receipt_epoch)?;
        occurred.push(t.started_at);
        epochs.push(epoch.map(|e| e.0));
        reasons.push(reason.map(crawlx_core::traffic::UnattributedReason::as_str));
        seqs.push(conv::<u64, i32>(t.seq, "traffic seq")?);
        origins.push(origin_label(t.origin));
        third.push(t.third_party);
        late.push(t.late);
        methods.push(t.method.as_str());
        hashes.push(Digest::of("crawlx/traffic-url/v1", t.url.as_bytes()).0.to_vec());
        statuses.push(t.status.map(i32::from));
        if zdr {
            // ZDR keeps url_hash, method and status only
            urls.push(None);
            req_h.push(None);
            resp_h.push(None);
        } else {
            urls.push(Some(t.url.as_str()));
            req_h.push(Some(to_json(&t.request_headers)?));
            resp_h.push(Some(to_json(&t.response_headers)?));
        }
        bodies.push(if zdr {
            None
        } else {
            t.response_body.as_ref().map(|a| a.id.0)
        });
        req_bodies.push(if zdr {
            None
        } else {
            t.request_body.as_ref().map(|a| a.id.0)
        });
        finished.push(t.finished_at);
    }
    sqlx::query(
        "INSERT INTO traffic_events (occurred_at, run_id, epoch_id, unattributed_reason, seq, lane, origin, third_party, late, method, url_redacted, url_hash, status, \
           request_headers, response_headers, body_artifact_id, request_body_artifact_id, finished_at) \
         SELECT t.occurred_at, $1::uuid, t.epoch_id, t.reason, t.seq, \
           (CASE WHEN t.epoch_id IS NULL THEN 'diagnostic' ELSE $2::text END)::trust_lane, t.origin, t.third_party, t.late, t.method, t.url_redacted, t.url_hash, \
           t.status, t.req_h, t.resp_h, t.body, t.req_body, t.finished_at \
         FROM UNNEST($3::timestamptz[], $4::uuid[], $5::text[], $6::int[], $7::text[], $8::bool[], $9::bool[], $10::text[], $11::text[], $12::bytea[], $13::int[], \
           $14::jsonb[], $15::jsonb[], $16::uuid[], $17::uuid[], $18::timestamptz[]) \
           AS t(occurred_at, epoch_id, reason, seq, origin, third_party, late, method, url_redacted, url_hash, status, req_h, resp_h, body, req_body, finished_at)",
    )
    .bind(run.0)
    .bind(lane.as_str())
    .bind(occurred)
    .bind(epochs)
    .bind(reasons)
    .bind(seqs)
    .bind(origins)
    .bind(third)
    .bind(late)
    .bind(methods)
    .bind(urls)
    .bind(hashes)
    .bind(statuses)
    .bind(req_h)
    .bind(resp_h)
    .bind(bodies)
    .bind(req_bodies)
    .bind(finished)
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    Ok(())
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
