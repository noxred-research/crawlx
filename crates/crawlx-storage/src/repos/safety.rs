//! `SafetyAudit` over `safety_decisions`.

use super::upsert_set;
use crate::backend::strategy::Conn;
use crate::backend::Dialect;
use crate::sql::{stmt, Sql};
use crate::store::Store;
use crate::{error::not_found, zdr_project};
use async_trait::async_trait;
use crawlx_core::repo::SafetyAudit;
use crawlx_core::safety::SafetyVerdict;
use crawlx_core::{CrawlRunId, SessionId, StoreError};

/// Insert (or link, on conflict) the `safety_decisions` row for `v`. `action` is
/// `None` for audit-only verdicts. The run's profile, policy version and
/// authorization record are read from `crawl_runs` in the same statement.
///
/// The evidence of a zero-data-retention run is reduced to a digest here before it is bound,
/// on every engine: PostgreSQL's trigger digests it as well and accepts the projected value
/// unchanged, so the content never reaches a statement even if the trigger were absent.
///
/// # Errors
/// Returns [`StoreError::NotFound`] when the run does not exist, otherwise any statement error.
pub(crate) async fn write_decision<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    session: SessionId,
    action: Option<uuid::Uuid>,
    v: &SafetyVerdict,
    summary: &str,
) -> Result<(), StoreError> {
    let evidence = serde_json::json!({ "summary": summary, "approval": v.approval.map(|a| a.0) });
    let (_, zdr) = Store::<B>::privacy_scope_tx(conn, run).await?;
    let evidence = zdr_project::safety_evidence(&evidence, zdr)?;
    let link = upsert_set::<B>(
        &["decision_id"],
        &format!(
            "action_id = COALESCE({}, safety_decisions.action_id), session_id = {}",
            <B::Dialect as Dialect>::excluded("action_id"),
            <B::Dialect as Dialect>::excluded("session_id")
        ),
    );
    let written = stmt!(
        B,
        format!(
            "INSERT INTO safety_decisions (decision_id, run_id, action_id, session_id, risk_class, verdict, profile, rules, evidence, policy_version, authorization_record_id) \
             SELECT $1::uuid, r.run_id, $3::uuid, $4::uuid, $5::text::risk_class, $6::text, r.safety_profile, $7::text[], $8::jsonb, r.policy_version, r.authorization_record_id \
             FROM crawl_runs r WHERE r.run_id = $2 \
             {link}"
        )
    )
    .uuid(v.decision_id.0)
    .uuid(run.0)
    .opt_uuid(action)
    .uuid(session.0)
    .text(v.risk_class.as_str())
    .text(v.decision.as_str())
    .text_list(&v.rules)
    .json(&evidence)
    .execute(conn)
    .await?;
    if written == 0 {
        return Err(not_found("crawl_run", run));
    }
    Ok(())
}

#[async_trait]
impl<B: Sql> SafetyAudit for Store<B> {
    async fn record(
        &self,
        run: CrawlRunId,
        session: SessionId,
        v: &SafetyVerdict,
        summary: &str,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("safety.record");
        let mut tx = self.begin_write().await?;
        write_decision::<B>(tx.conn(), run, session, None, v, summary).await?;
        tx.commit().await
    }
}
