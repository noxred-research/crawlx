//! Durable reviewer decisions and the asynchronous, fenced approval bridge.
//!
//! A preview is never execution authority. Consumption commits before the synchronous
//! kernel receives a one-shot capability. A crash in between spends approval without
//! execution. The original parked action is reused at T1; no second action is created.
//!
//! Statements run only through [`crate::tenant::ScopedQuery`]; the module denies the raw
//! statement entry points (see `clippy.toml`).

#![deny(clippy::disallowed_methods)]

use crate::backend::strategy::Conn;
use crate::backend::{BackendKind, Dialect as _, RowLock};
use crate::codec::{conv, from_json, to_json};
use crate::leases::SessionLease;
use crate::repos::write_decision;
use crate::sql::{Sql, SqlRow, Stmt};
use crate::store::Store;
use crate::tenant::{Dia, Scope, ScopedQuery};
use crate::ApprovalRecord;
use async_trait::async_trait;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::safety::{RiskClass, SafetyDecision, SafetyVerdict};
use crawlx_core::{
    ActionContextId, ActionId, ApprovalId, CrawlRunId, SessionId, StoreError, TenantId, Timestamp,
};
use serde::{Deserialize, Serialize};

/// Complete immutable binding checked both at durable consume and kernel admission.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ApprovalBindingV1 {
    /// Tenant from trusted run ownership.
    pub tenant: TenantId,
    /// Run from the active session lease.
    pub run: CrawlRunId,
    /// Session from the active session lease.
    pub session: SessionId,
    /// Original parked action, never a replacement action.
    pub action: ActionId,
    /// Exact action-context digest.
    pub action_key: ActionContextId,
    /// Reclassified risk.
    pub risk: RiskClass,
    /// Exact non-secret parameters digest produced by the kernel.
    pub params_digest: Digest,
    /// Exact observed epoch, with no mutation slack.
    pub epoch: ObservationEpoch,
}

impl ApprovalBindingV1 {
    /// Bind a parked proposal to its trusted tenant and lease.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        lease: &SessionLease,
        action: ActionId,
        action_key: ActionContextId,
        risk: RiskClass,
        params_digest: Digest,
        epoch: ObservationEpoch,
    ) -> Self {
        Self {
            tenant,
            run: lease.session.run,
            session: lease.session.id,
            action,
            action_key,
            risk,
            params_digest,
            epoch,
        }
    }
}

/// Exact kernel request, persisted without extending its deadline.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ApprovalRequestV1 {
    /// Kernel-issued identifier.
    pub id: ApprovalId,
    /// Immutable trusted binding.
    pub binding: ApprovalBindingV1,
    /// Redacted summary only; never raw target text or action parameters.
    pub summary: String,
    /// Original issue instant.
    pub created_at: Timestamp,
    /// Original expiry, already capped by the run deadline.
    pub expires_at: Timestamp,
}

impl ApprovalRequestV1 {
    /// Preserve the kernel's exact issue time and deadline.
    #[must_use]
    pub fn new(
        id: ApprovalId,
        binding: ApprovalBindingV1,
        summary: String,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            id,
            binding,
            summary,
            created_at,
            expires_at,
        }
    }

    pub(crate) fn validate(&self, now: Timestamp) -> Result<(), StoreError> {
        if self.created_at > now
            || self.expires_at <= now
            || self.expires_at <= self.created_at
            || self.expires_at.signed_duration_since(self.created_at) > chrono::Duration::hours(24)
            || self.summary.len() > 16_384
        {
            return Err(conflict());
        }
        Ok(())
    }
}

/// Persisted reviewer snapshot; useful for ranking, never sufficient for admission.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct DurableApprovalV1 {
    /// Exact immutable request.
    pub request: ApprovalRequestV1,
    /// API-visible decision and audit timestamps.
    pub record: ApprovalRecord,
}

impl DurableApprovalV1 {
    /// Pair untrusted preview data. Consumption always reloads and verifies durable state.
    #[must_use]
    pub fn new(request: ApprovalRequestV1, record: ApprovalRecord) -> Self {
        Self { request, record }
    }
}

/// Receipt created only after a single-use consume transaction commits.
/// Deliberately not cloneable or deserializable.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConsumedApprovalV1 {
    /// Exact request that was spent.
    pub request: ApprovalRequestV1,
    /// Active session lease fence checked during consumption.
    pub fence: i64,
    /// Database time, or injected memory time, at consumption.
    pub consumed_at: Timestamp,
}

pub(crate) fn conflict() -> StoreError {
    StoreError::Conflict("approval unavailable, expired, spent or binding changed".into())
}

/// Asynchronous trusted boundary. No implementation may hide blocking I/O in a kernel store.
#[async_trait]
pub trait ApprovalRepository: Send + Sync {
    /// Bind the journal's pending approval to the exact kernel request.
    /// Repeating an identical request is idempotent; legacy unbound rows cannot execute.
    ///
    /// # Errors
    /// Returns lease loss, binding conflict, expired request or repository errors.
    async fn persist_approval(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        request: &ApprovalRequestV1,
    ) -> Result<(), StoreError>;

    /// Find an approved request for this exact observed proposal, preserving parked action identity.
    ///
    /// # Errors
    /// Returns lease loss, authorization denial or repository errors.
    async fn find_approval(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        key: ActionContextId,
        risk: RiskClass,
        params: Digest,
        epoch: ObservationEpoch,
    ) -> Result<Option<DurableApprovalV1>, StoreError>;

    /// Atomically spend an approved, unexpired, unrevoked request under the active lease.
    ///
    /// # Errors
    /// Returns lease loss or conflict for every mismatch, denial, expiry or replay.
    async fn consume_approval(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        expected: &DurableApprovalV1,
    ) -> Result<ConsumedApprovalV1, StoreError>;

    /// After live authorization, epoch validation and kernel confirmation, journal T1 on the
    /// original action. Rechecks expiry, revocation and fence; links the new allow decision.
    ///
    /// # Errors
    /// Returns lease loss, conflict, invalid verdict or repository errors. Nothing may execute
    /// unless this transaction commits successfully.
    async fn intend_approved(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        action: ActionId,
        epoch: ObservationEpoch,
        verdict: &SafetyVerdict,
    ) -> Result<(), StoreError>;
}

/// Approvals scanned per round trip while looking for the exact bound request.
const FIND_PAGE: i64 = 32;

// Lock order: session, run, authorization, approval, action. The session validator
// and `FOR UPDATE OF` are PostgreSQL forms; the other engines lock the same rows one
// statement at a time in the same order.
// Database time is read after all authority locks, never supplied by API callers.
async fn lock_authority<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    lease: &SessionLease,
) -> Result<Timestamp, StoreError> {
    if B::KIND == BackendKind::Postgres {
        ScopedQuery::within_scope(Stmt::<B>::dynamic("SET LOCAL synchronous_commit = on"))
            .execute(conn)
            .await?;
    }
    crate::session_binding::lock_lease_on::<B>(conn, lease, tenant).await?;
    let lock = format!(
        "SELECT run_id FROM crawl_runs WHERE run_id=$1 AND tenant_id=$2{}",
        Dia::<B>::row_lock(RowLock::Update)
    );
    ScopedQuery::within_scope(Stmt::<B>::dynamic(&lock).uuid(lease.session.run.0).uuid(tenant.0))
        .fetch_optional(conn)
        .await?
        .ok_or(StoreError::LeaseLost)?;
    if B::KIND == BackendKind::Postgres {
        ScopedQuery::within_scope(
            Stmt::<B>::dynamic(
                "SELECT z.record_id FROM authorization_records z JOIN crawl_runs r ON r.authorization_record_id=z.record_id WHERE r.run_id=$1 FOR UPDATE OF z",
            )
            .uuid(lease.session.run.0),
        )
        .fetch_optional(conn)
        .await?;
    } else if let Some(record) = ScopedQuery::within_scope(
        Stmt::<B>::dynamic("SELECT authorization_record_id FROM crawl_runs WHERE run_id=$1")
            .uuid(lease.session.run.0),
    )
    .fetch_optional(conn)
    .await?
    .map(|r| r.opt_uuid("authorization_record_id"))
    .transpose()?
    .flatten()
    {
        let lock = format!(
            "SELECT record_id FROM authorization_records WHERE record_id=$1{}",
            Dia::<B>::row_lock(RowLock::Update)
        );
        ScopedQuery::within_scope(Stmt::<B>::dynamic(&lock).uuid(record))
            .fetch_optional(conn)
            .await?;
    }
    let now = crate::session_binding::lock_lease_on::<B>(conn, lease, tenant).await?;
    let valid = ScopedQuery::within_scope(
        Stmt::<B>::dynamic(
            "SELECT NOT EXISTS(SELECT 1 FROM crawl_runs r LEFT JOIN authorization_records z ON z.record_id=r.authorization_record_id \
             WHERE r.run_id=$1 AND r.authorization_record_id IS NOT NULL AND (z.record_id IS NULL OR z.tenant_id<>r.tenant_id \
             OR z.verified_at IS NULL OR z.revoked_at IS NOT NULL OR z.valid_from>$2 OR z.valid_to<=$2 \
             OR z.body_digest<>r.authorization_body_digest OR r.authorization_body_digest IS NULL)) AS v",
        )
        .uuid(lease.session.run.0)
        .ts(now),
    )
    .fetch_one(conn)
    .await?
    .flag("v")?;
    if !valid {
        return Err(StoreError::LeaseLost);
    }
    Ok(now)
}

async fn lock_request<B: Sql>(conn: &mut Conn<B>, id: ApprovalId) -> Result<ApprovalRequestV1, StoreError> {
    let sql = format!(
        "SELECT request_payload FROM approvals WHERE approval_id=$1{}",
        Dia::<B>::row_lock(RowLock::Update)
    );
    let row = ScopedQuery::within_scope(Stmt::<B>::dynamic(&sql).uuid(id.0))
        .fetch_optional(conn)
        .await?
        .ok_or_else(conflict)?;
    from_json(row.opt_json("request_payload")?.ok_or_else(conflict)?)
}

async fn check_action<B: Sql>(
    conn: &mut Conn<B>,
    binding: &ApprovalBindingV1,
    lease: &SessionLease,
    tenant: TenantId,
) -> Result<(), StoreError> {
    if binding.tenant != tenant || binding.run != lease.session.run || binding.session != lease.session.id {
        return Err(conflict());
    }
    let sql = format!(
        "SELECT a.run_id, a.session_id, a.status::text AS status, a.epoch_navigation, a.epoch_document, a.epoch_mutation, c.context_hash \
         FROM actions a JOIN action_contexts c ON c.context_id=a.context_id WHERE a.action_id=$1{}",
        Dia::<B>::row_lock(RowLock::Update)
    );
    let row = ScopedQuery::within_scope(Stmt::<B>::dynamic(&sql).uuid(binding.action.0))
        .fetch_optional(conn)
        .await?
        .ok_or_else(conflict)?;
    if row.uuid("run_id")? != binding.run.0
        || row.uuid("session_id")? != binding.session.0
        || row.text("status")? != "proposed"
        || row.bytes("context_hash")?.as_slice() != binding.action_key.0
        || row.i64("epoch_navigation")? != conv::<u64, i64>(binding.epoch.navigation_seq, "epoch")?
        || row.i64("epoch_document")? != conv::<u64, i64>(binding.epoch.document_seq, "epoch")?
        || row.i64("epoch_mutation")? != conv::<u64, i64>(binding.epoch.mutation_seq, "epoch")?
    {
        return Err(conflict());
    }
    Ok(())
}

impl<B: Sql> Store<B> {
    /// Approvals are worker authority: with a tenant scope active they may only act for it.
    fn approval_scope(&self, tenant: TenantId) -> Result<Scope, StoreError> {
        let scope = self.scope()?;
        scope.authorize(tenant)?;
        Ok(scope)
    }
}

#[async_trait]
impl<B: Sql> ApprovalRepository for Store<B> {
    async fn persist_approval(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        request: &ApprovalRequestV1,
    ) -> Result<(), StoreError> {
        let scope = self.approval_scope(tenant)?;
        let mut tx = self.begin_write().await?;
        let now = lock_authority::<B>(tx.conn(), tenant, lease).await?;
        request.validate(now)?;
        let sql = format!(
            "SELECT request_payload, run_id, action_id, risk_class::text AS risk_class, decision, consumed_at, revoked_at FROM approvals WHERE approval_id=$1{}",
            Dia::<B>::row_lock(RowLock::Update)
        );
        let row = scope
            .query("approvals", Stmt::<B>::dynamic(&sql).uuid(request.id.0))?
            .fetch_optional(tx.conn())
            .await?
            .ok_or_else(conflict)?;
        let old = row.opt_json("request_payload")?;
        if let Some(old) = old {
            if from_json::<ApprovalRequestV1>(old)? != *request {
                return Err(conflict());
            }
            check_action::<B>(tx.conn(), &request.binding, lease, tenant).await?;
            return tx.commit().await;
        }
        if row.uuid("run_id")? != request.binding.run.0
            || row.uuid("action_id")? != request.binding.action.0
            || row.text("risk_class")? != request.binding.risk.as_str()
            || !matches!(row.text("decision")?.as_str(), "pending" | "approved" | "denied")
            || row.opt_ts("consumed_at")?.is_some()
            || row.opt_ts("revoked_at")?.is_some()
        {
            return Err(conflict());
        }
        check_action::<B>(tx.conn(), &request.binding, lease, tenant).await?;
        let payload = to_json(request)?;
        scope
            .query(
                "approvals",
                Stmt::<B>::dynamic(
                    "UPDATE approvals SET request_payload=$2, requested_at=$3, expires_at=$4, bound_action_id=action_id WHERE approval_id=$1",
                )
                .uuid(request.id.0)
                .json(&payload)
                .ts(request.created_at)
                .ts(request.expires_at),
            )?
            .execute(tx.conn())
            .await?;
        tx.commit().await
    }

    async fn find_approval(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        key: ActionContextId,
        risk: RiskClass,
        params: Digest,
        epoch: ObservationEpoch,
    ) -> Result<Option<DurableApprovalV1>, StoreError> {
        let scope = self.approval_scope(tenant)?;
        let mut tx = self.begin_write().await?;
        let now = lock_authority::<B>(tx.conn(), tenant, lease).await?;
        // Scan candidate payloads page by page rather than materializing every approval for a
        // context. SQL narrows immutable action epochs/risk; the exact parameter digest is
        // checked against the typed request before any snapshot leaves this boundary.
        let sql = format!(
            "SELECT p.request_payload, p.approval_id FROM approvals p JOIN actions a ON a.action_id=p.action_id \
             JOIN action_contexts c ON c.context_id=a.context_id WHERE p.run_id=$1 AND a.session_id=$2 AND c.context_hash=$3 \
             AND p.decision='approved' AND p.consumed_at IS NULL AND p.revoked_at IS NULL AND p.expires_at>$4 \
             AND a.epoch_navigation=$5 AND a.epoch_document=$6 AND a.epoch_mutation=$7 \
             AND p.risk_class::text=$8 \
             AND p.request_payload IS NOT NULL AND a.status='proposed' AND ($9::uuid IS NULL OR p.approval_id>$9) \
             ORDER BY p.approval_id LIMIT {FIND_PAGE}"
        );
        let navigation = conv::<u64, i64>(epoch.navigation_seq, "epoch")?;
        let document = conv::<u64, i64>(epoch.document_seq, "epoch")?;
        let mutation = conv::<u64, i64>(epoch.mutation_seq, "epoch")?;
        let mut after: Option<uuid::Uuid> = None;
        loop {
            let rows = scope
                .query(
                    "approvals",
                    Stmt::<B>::dynamic(&sql)
                        .uuid(lease.session.run.0)
                        .uuid(lease.session.id.0)
                        .bytes(key.0.as_slice())
                        .ts(now)
                        .i64(navigation)
                        .i64(document)
                        .i64(mutation)
                        .text(risk.as_str())
                        .opt_uuid(after),
                )?
                .fetch_all(tx.conn())
                .await?;
            for row in &rows {
                let request: ApprovalRequestV1 = from_json(row.json("request_payload")?)?;
                if request.binding.tenant == tenant
                    && request.binding.run == lease.session.run
                    && request.binding.session == lease.session.id
                    && request.binding.action_key == key
                    && request.binding.risk == risk
                    && request.binding.params_digest == params
                    && request.binding.epoch == epoch
                    && request.expires_at > now
                {
                    let record =
                        crate::repos::api::approval_in_transaction::<B>(tx.conn(), request.id).await?;
                    tx.commit().await?;
                    return Ok(Some(DurableApprovalV1 { request, record }));
                }
            }
            match rows.last() {
                Some(last) if i64::try_from(rows.len()).is_ok_and(|n| n == FIND_PAGE) => {
                    after = Some(last.uuid("approval_id")?);
                }
                _ => break,
            }
        }
        tx.commit().await?;
        Ok(None)
    }

    async fn consume_approval(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        expected: &DurableApprovalV1,
    ) -> Result<ConsumedApprovalV1, StoreError> {
        let scope = self.approval_scope(tenant)?;
        let mut tx = self.begin_write().await?;
        lock_authority::<B>(tx.conn(), tenant, lease).await?;
        let request = lock_request::<B>(tx.conn(), expected.request.id).await?;
        if request != expected.request {
            return Err(conflict());
        }
        check_action::<B>(tx.conn(), &request.binding, lease, tenant).await?;
        let now = lock_authority::<B>(tx.conn(), tenant, lease).await?;
        request.validate(now)?;
        let spent = scope
            .query(
                "approvals",
                Stmt::<B>::dynamic(
                    "UPDATE approvals SET consumed_at=$2, consumed_fence=$3 WHERE approval_id=$1 AND run_id=$4 AND action_id=$5 \
                     AND decision='approved' AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>$2 AND decided_at<=$2",
                )
                .uuid(request.id.0)
                .ts(now)
                .i64(lease.fencing_token)
                .uuid(request.binding.run.0)
                .uuid(request.binding.action.0),
            )?
            .execute(tx.conn())
            .await?;
        if spent != 1 {
            return Err(conflict());
        }
        tx.commit().await?;
        Ok(ConsumedApprovalV1 {
            request,
            fence: lease.fencing_token,
            consumed_at: now,
        })
    }

    async fn intend_approved(
        &self,
        tenant: TenantId,
        lease: &SessionLease,
        action: ActionId,
        epoch: ObservationEpoch,
        verdict: &SafetyVerdict,
    ) -> Result<(), StoreError> {
        let scope = self.approval_scope(tenant)?;
        let id = verdict.approval.ok_or_else(conflict)?;
        if verdict.decision != SafetyDecision::Allow {
            return Err(conflict());
        }
        let mut tx = self.begin_write().await?;
        lock_authority::<B>(tx.conn(), tenant, lease).await?;
        let request = lock_request::<B>(tx.conn(), id).await?;
        if request.binding.action != action
            || request.binding.epoch != epoch
            || request.binding.risk != verdict.risk_class
        {
            return Err(conflict());
        }
        check_action::<B>(tx.conn(), &request.binding, lease, tenant).await?;
        let now = lock_authority::<B>(tx.conn(), tenant, lease).await?;
        request.validate(now)?;
        let valid = scope
            .query(
                "approvals",
                Stmt::<B>::dynamic(
                    "SELECT EXISTS(SELECT 1 FROM approvals WHERE approval_id=$1 AND consumed_fence=$2 AND consumed_at<=$3 \
                     AND decision='approved' AND revoked_at IS NULL AND expires_at>$3 AND bound_action_id=$4) AS v",
                )
                .uuid(id.0)
                .i64(lease.fencing_token)
                .ts(now)
                .uuid(action.0),
            )?
            .fetch_one(tx.conn())
            .await?
            .flag("v")?;
        if !valid {
            return Err(conflict());
        }
        write_decision::<B>(
            tx.conn(),
            lease.session.run,
            lease.session.id,
            Some(action.0),
            verdict,
            &request.summary,
        )
        .await?;
        scope
            .query(
                "approvals",
                Stmt::<B>::dynamic("UPDATE approvals SET safety_decision_id=$2 WHERE approval_id=$1")
                    .uuid(id.0)
                    .uuid(verdict.decision_id.0),
            )?
            .execute(tx.conn())
            .await?;
        scope
            .query(
                "actions",
                Stmt::<B>::dynamic(
                    "UPDATE actions SET status='intended', hold='none', intended_at=$2, finished_at=NULL, safety_decision_id=$3, \
                     before_state_id=(SELECT state_id FROM states WHERE session_id=$4 AND epoch_navigation=$5 AND epoch_document=$6 \
                     AND epoch_mutation<=$7 ORDER BY epoch_mutation DESC, observed_at DESC LIMIT 1) WHERE action_id=$1",
                )
                .uuid(action.0)
                .ts(now)
                .uuid(verdict.decision_id.0)
                .uuid(lease.session.id.0)
                .i64(conv::<u64, i64>(epoch.navigation_seq, "epoch")?)
                .i64(conv::<u64, i64>(epoch.document_seq, "epoch")?)
                .i64(conv::<u64, i64>(epoch.mutation_seq, "epoch")?),
            )?
            .execute(tx.conn())
            .await?;
        scope
            .query(
                "action_contexts",
                Stmt::<B>::dynamic(
                    "UPDATE action_contexts SET attempts=attempts+1 WHERE context_id=(SELECT context_id FROM actions WHERE action_id=$1)",
                )
                .uuid(action.0),
            )?
            .execute(tx.conn())
            .await?;
        tx.commit().await
    }
}
