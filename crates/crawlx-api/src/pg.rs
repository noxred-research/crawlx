//! PostgreSQL implementation of [`ApiStore`] and [`Eraser`].
//!
//! This module holds no SQL: every statement lives in
//! `crawlx-storage`. [`PgApiStore`] delegates to [`PgApiRepo`] for the API-owned
//! tables (`api_keys`, `idempotency_keys`, `approvals`, `transitions`,
//! `webhook_deliveries`, `authorization_records`, replay tagging), to
//! [`TrustedCorpus`] for traffic and coverage and to [`append_audit`] for the audit
//! chain, and converts between the repository's row types and the API's own
//! ([`KeyRecord`], [`IdemBegin`], [`TrafficRecord`], `AuthorizationRecord`).
//! The PostgreSQL tests of this store live in `tests/api_store_pg.rs`.

use crate::store::{
    without_lifecycle, ApiStore, ApprovalDecision, ApprovalRecord, ArtifactSource, AuthorizationEntry,
    AuthorizationInsert, AuthorizationRevoked, DecideOutcome, DeliveryResult, Eraser, IdemBegin, KeyRecord,
    Scope, StoreResult, StoredResponse, TrafficFilter, TrafficRecord, TransitionFilter, TransitionRecord,
    WebhookDelivery,
};
use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::{ApprovalId, AuthorizationRecordId, CrawlRunId, StoreError, TenantId, Timestamp};
use crawlx_policy::AuthorizationRecord;
use crawlx_storage::retention::{append_audit, RetentionSweeper};
use crawlx_storage::trusted::{CorpusTrafficEvent, CoverageRow, LaneFilter, TrafficQuery, TrustedCorpus};
use crawlx_storage::{
    ApiKeyRow, IdemClaim, IdemResponse, NewAuthorization, Pg, PgApiRepo, StoredAuthorization, TenantEngine,
};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

/// [`ApiStore`] over PostgreSQL.
#[derive(Clone, Debug)]
pub struct PgApiStore {
    repo: PgApiRepo,
    corpus: TrustedCorpus,
    pg: Pg,
}

impl PgApiStore {
    /// API store over the shared PostgreSQL pool.
    #[must_use]
    pub fn new(pg: Pg) -> Self {
        Self {
            repo: PgApiRepo::new(pg.clone()),
            corpus: TrustedCorpus::new(pg.clone()),
            pg,
        }
    }
}

fn key_record(row: ApiKeyRow) -> KeyRecord {
    KeyRecord {
        key_id: row.key_id,
        tenant: row.tenant,
        prefix: row.prefix,
        hash: row.hash,
        // unknown scope labels are ignored
        scopes: row.scopes.iter().filter_map(|s| Scope::parse(s)).collect(),
        expires_at: row.expires_at,
        revoked: row.revoked,
    }
}

fn key_row(key: &KeyRecord) -> ApiKeyRow {
    ApiKeyRow {
        key_id: key.key_id,
        tenant: key.tenant,
        prefix: key.prefix.clone(),
        hash: key.hash,
        scopes: key.scopes.iter().map(|s| s.as_str().to_owned()).collect(),
        expires_at: key.expires_at,
        revoked: key.revoked,
    }
}

/// The API's view of a stored record: the JSON merged by the repository, parsed.
fn authorization_entry(
    id: AuthorizationRecordId,
    stored: StoredAuthorization,
) -> StoreResult<AuthorizationEntry> {
    let record = serde_json::from_value(stored.body)
        .map_err(|e| StoreError::Serialization(format!("authorization record {id}: {e}")))?;
    Ok(AuthorizationEntry {
        record,
        body_digest: stored.body_digest,
        verification: stored.verification,
    })
}

fn stored_response(r: IdemResponse) -> StoredResponse {
    StoredResponse {
        status: r.status,
        body: r.body,
        run_id: r.run_id,
    }
}

fn traffic_record(e: CorpusTrafficEvent) -> TrafficRecord {
    let empty = || Value::Object(serde_json::Map::new());
    TrafficRecord {
        // zero-padded so the lexicographic order equals the persisted (`event_id`) order
        id: format!("{:020}", e.event_id),
        epoch_id: e.epoch,
        action: e.action,
        lane: e.lane,
        role: e.role,
        origin: e.origin,
        method: e.method,
        url: e.url_redacted.unwrap_or_default(),
        status: e.status,
        third_party: e.third_party,
        late: e.late,
        request_headers: e.request_headers.unwrap_or_else(empty),
        response_headers: e.response_headers.unwrap_or_else(empty),
        // the body ArtifactRef needs a digest that traffic_events does not carry
        response_body: None,
        occurred_at: e.occurred_at,
    }
}

#[async_trait]
impl ApiStore for PgApiStore {
    // ---- API keys -------------------------------------------------------

    async fn key_by_prefix(&self, prefix: &str) -> StoreResult<Option<KeyRecord>> {
        Ok(self.repo.key_by_prefix(prefix).await?.map(key_record))
    }

    async fn key_insert(&self, key: &KeyRecord, tenant_name: &str) -> StoreResult<()> {
        self.repo.key_insert(&key_row(key), tenant_name).await
    }

    async fn key_touch(&self, key_id: Uuid, at: Timestamp) -> StoreResult<()> {
        self.repo.key_touch(key_id, at).await
    }

    // ---- idempotency ------------------------------------------------------

    async fn idem_begin(
        &self,
        tenant: TenantId,
        key: &str,
        request_hash: Digest,
        now: Timestamp,
    ) -> StoreResult<IdemBegin> {
        Ok(
            match self.repo.idem_begin(tenant, key, request_hash, now).await? {
                IdemClaim::Started => IdemBegin::Started,
                IdemClaim::Done(r) => IdemBegin::Replay(stored_response(r)),
                IdemClaim::InProgress => IdemBegin::InProgress,
                IdemClaim::Mismatch => IdemBegin::Mismatch,
            },
        )
    }

    async fn idem_complete(&self, tenant: TenantId, key: &str, response: &StoredResponse) -> StoreResult<()> {
        let response = IdemResponse {
            status: response.status,
            body: response.body.clone(),
            run_id: response.run_id,
        };
        self.repo.idem_complete(tenant, key, &response).await
    }

    async fn idem_release(&self, tenant: TenantId, key: &str) -> StoreResult<()> {
        self.repo.idem_release(tenant, key).await
    }

    async fn idem_link_run(&self, tenant: TenantId, key: &str, run: CrawlRunId) -> StoreResult<()> {
        self.repo.idem_link_run(tenant, key, run).await
    }

    async fn idem_run(&self, tenant: TenantId, key: &str) -> StoreResult<Option<CrawlRunId>> {
        self.repo.idem_run(tenant, key).await
    }

    // ---- approvals --------------------------------------------------------

    async fn approvals_list(&self, run: CrawlRunId) -> StoreResult<Vec<ApprovalRecord>> {
        self.repo.approvals_list(run).await
    }

    async fn approval_get(&self, run: CrawlRunId, id: ApprovalId) -> StoreResult<Option<ApprovalRecord>> {
        self.repo.approval_get(run, id).await
    }

    async fn approval_decide(
        &self,
        run: CrawlRunId,
        id: ApprovalId,
        decision: ApprovalDecision,
        decided_by: Uuid,
        reason: Option<&str>,
        now: Timestamp,
    ) -> StoreResult<DecideOutcome> {
        self.repo
            .approval_decide(run, id, decision, decided_by, reason, now)
            .await
    }

    // ---- transitions, traffic, coverage -------------------------------------

    async fn transitions_list(
        &self,
        run: CrawlRunId,
        filter: &TransitionFilter,
    ) -> StoreResult<Vec<TransitionRecord>> {
        self.repo.transitions_list(run, filter).await
    }

    async fn traffic_list(&self, run: CrawlRunId, filter: &TrafficFilter) -> StoreResult<Vec<TrafficRecord>> {
        let query = TrafficQuery {
            role: filter.role.as_deref(),
            epoch: filter.epoch,
            origin: filter.origin,
        };
        let events = self
            .corpus
            .traffic(run, LaneFilter::from(filter.lane), &query)
            .await?;
        Ok(events.into_iter().map(traffic_record).collect())
    }

    async fn coverage(&self, run: CrawlRunId) -> StoreResult<Vec<CoverageRow>> {
        self.corpus.coverage(run).await
    }

    // ---- runs -------------------------------------------------------------

    async fn active_run_count(&self, tenant: TenantId) -> StoreResult<u64> {
        self.repo.active_run_count(tenant).await
    }

    async fn active_runs(&self, tenant: TenantId) -> StoreResult<Vec<CrawlRunId>> {
        self.repo.active_runs(tenant).await
    }

    async fn run_created(&self, _tenant: TenantId, _run: CrawlRunId) -> StoreResult<()> {
        Ok(())
    }

    async fn shadow_tag(&self, run: CrawlRunId) -> StoreResult<()> {
        self.repo.shadow_tag(run).await
    }

    async fn tenant_engine(&self, tenant: TenantId) -> StoreResult<TenantEngine> {
        Ok(crawlx_storage::admin::tenant_engine_of(&self.pg, tenant)
            .await?
            .unwrap_or_default())
    }

    async fn authorization_get(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> StoreResult<Option<AuthorizationRecord>> {
        let Some(body) = self.repo.authorization_get(tenant, id).await? else {
            return Ok(None);
        };
        serde_json::from_value(body)
            .map(Some)
            .map_err(|e| StoreError::Serialization(format!("authorization record {id}: {e}")))
    }

    async fn authorization_entry(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> StoreResult<Option<AuthorizationEntry>> {
        self.repo
            .authorization_stored(tenant, id)
            .await?
            .map(|stored| authorization_entry(id, stored))
            .transpose()
    }

    async fn authorization_create(
        &self,
        tenant: TenantId,
        created_by: Uuid,
        record: &AuthorizationRecord,
        verification: &Value,
        verified_at: Timestamp,
    ) -> StoreResult<AuthorizationInsert> {
        let record = without_lifecycle(record);
        let body = serde_json::to_value(&record).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let digest = record
            .body_digest()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        let version = i32::try_from(record.version)
            .map_err(|_| StoreError::Serialization("authorization record version out of range".to_owned()))?;
        self.repo
            .authorization_create(&NewAuthorization {
                tenant,
                id: record.id,
                version,
                body: &body,
                body_digest: &digest.0,
                valid_from: record.valid_from,
                valid_to: record.valid_to,
                created_by,
                verified_at,
                verification,
            })
            .await
    }

    async fn authorization_revoke(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        by: Uuid,
        reason: Option<&str>,
        now: Timestamp,
    ) -> StoreResult<Option<AuthorizationRevoked>> {
        self.repo
            .authorization_revoke(tenant, id, by, reason, now)
            .await?
            .map(|revoked| {
                Ok(AuthorizationRevoked {
                    entry: authorization_entry(id, revoked.stored)?,
                    first: revoked.first,
                })
            })
            .transpose()
    }

    async fn authorization_mark_verified(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        verification: &Value,
        now: Timestamp,
    ) -> StoreResult<Option<AuthorizationEntry>> {
        self.repo
            .authorization_mark_verified(tenant, id, verification, now)
            .await?
            .map(|stored| authorization_entry(id, stored))
            .transpose()
    }

    async fn authorization_bind_run(&self, run: CrawlRunId, body_digest: Digest) -> StoreResult<()> {
        self.repo.authorization_bind_run(run, body_digest).await
    }

    async fn authorization_run_digest(&self, run: CrawlRunId) -> StoreResult<Option<Digest>> {
        self.repo.authorization_run_digest(run).await
    }

    // ---- audit ------------------------------------------------------------

    async fn audit_append(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        actor: &str,
        event: &str,
        subject: Value,
    ) -> StoreResult<()> {
        append_audit(&self.pg, Some(tenant.0), run.map(|r| r.0), actor, event, subject).await
    }

    // ---- webhook outbox -----------------------------------------------------

    async fn webhook_runs(&self) -> StoreResult<Vec<CrawlRunId>> {
        self.repo.webhook_runs().await
    }

    /// Webhook runs are derived from `crawl_runs.config`; nothing to remember.
    async fn webhook_watch(&self, _run: CrawlRunId) -> StoreResult<()> {
        Ok(())
    }

    async fn webhook_cursor(&self, run: CrawlRunId) -> StoreResult<u64> {
        self.repo.webhook_cursor(run).await
    }

    async fn webhook_enqueue(&self, d: &WebhookDelivery) -> StoreResult<bool> {
        self.repo.webhook_enqueue(d).await
    }

    async fn webhook_claim_due(
        &self,
        now: Timestamp,
        limit: u32,
        lease_secs: u32,
    ) -> StoreResult<Vec<WebhookDelivery>> {
        self.repo.webhook_claim_due(now, limit, lease_secs).await
    }

    async fn webhook_record(&self, id: Uuid, result: &DeliveryResult) -> StoreResult<()> {
        self.repo.webhook_record(id, result).await
    }

    async fn webhook_dead_count(&self, run: CrawlRunId) -> StoreResult<u64> {
        self.repo.webhook_dead_count(run).await
    }

    async fn webhook_list(&self, run: CrawlRunId) -> StoreResult<Vec<WebhookDelivery>> {
        self.repo.webhook_list(run).await
    }
}

/// Erases a run: object-store artifacts first, then every database row
/// ([`RetentionSweeper::purge_run`], which also writes the audit-chain entry).
pub struct PgEraser {
    pg: Pg,
    artifacts: Option<Arc<dyn ArtifactSource>>,
}

impl PgEraser {
    /// Eraser that purges a run's rows and, when `artifacts` is set, its artifact objects.
    #[must_use]
    pub fn new(pg: Pg, artifacts: Option<Arc<dyn ArtifactSource>>) -> Self {
        Self { pg, artifacts }
    }
}

#[async_trait]
impl Eraser for PgEraser {
    async fn erase(&self, run: CrawlRunId) -> StoreResult<u64> {
        let sweeper = RetentionSweeper::new(self.pg.clone());
        let tenant = sweeper.begin_run_erasure(run).await?;
        if let Some(artifacts) = &self.artifacts {
            crate::store::erase_archives(&self.pg, artifacts.as_ref(), tenant, run.0).await?;
            artifacts.purge_run(run).await?;
        }
        sweeper.purge_run(run).await
    }
}
