//! `SafetyAudit` over `safety_decisions`.

use crate::codec::to_json;
use crate::error::{db, not_found};
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::repo::SafetyAudit;
use crawlx_core::safety::SafetyVerdict;
use crawlx_core::{CrawlRunId, SessionId, StoreError};
use sqlx::PgConnection;

/// Insert (or link, on conflict) the `safety_decisions` row for `v`. `action` is
/// `None` for audit-only verdicts. The run's profile, policy version and
/// authorization record are read from `crawl_runs` in the same statement.
pub(crate) async fn write_decision(
    conn: &mut PgConnection,
    run: CrawlRunId,
    session: SessionId,
    action: Option<uuid::Uuid>,
    v: &SafetyVerdict,
    summary: &str,
) -> Result<(), StoreError> {
    let evidence = serde_json::json!({ "summary": summary, "approval": v.approval.map(|a| a.0) });
    let r = sqlx::query(
        "INSERT INTO safety_decisions (decision_id, run_id, action_id, session_id, risk_class, verdict, profile, rules, evidence, policy_version, authorization_record_id) \
         SELECT $1::uuid, r.run_id, $3::uuid, $4::uuid, $5::text::risk_class, $6::text, r.safety_profile, $7::text[], $8::jsonb, r.policy_version, r.authorization_record_id \
         FROM crawl_runs r WHERE r.run_id = $2 \
         ON CONFLICT (decision_id) DO UPDATE SET action_id = COALESCE(EXCLUDED.action_id, safety_decisions.action_id), session_id = EXCLUDED.session_id",
    )
    .bind(v.decision_id.0)
    .bind(run.0)
    .bind(action)
    .bind(session.0)
    .bind(v.risk_class.as_str())
    .bind(v.decision.as_str())
    .bind(&v.rules)
    .bind(to_json(&evidence)?)
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    if r.rows_affected() == 0 {
        return Err(not_found("crawl_run", run));
    }
    Ok(())
}

#[async_trait]
impl SafetyAudit for Pg {
    async fn record(
        &self,
        run: CrawlRunId,
        session: SessionId,
        v: &SafetyVerdict,
        summary: &str,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("safety.record");
        let mut tx = self.pool.begin().await.map_err(db)?;
        write_decision(&mut tx, run, session, None, v, summary).await?;
        tx.commit().await.map_err(db)
    }
}
