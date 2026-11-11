//! [`MemoryApiStore`]: the in-memory [`ApiStore`] used by tests, development
//! and `database_url = None`. It reads actions and traffic from the shared
//! [`MemoryStore`] so transitions and traffic reflect what the worker journaled.
//!
//! The shared authorization lifecycle and run body bindings also authorize HEAD response
//! reads and publication in [`MemoryStore`]. Every check reads this store's current state,
//! including for completed runs; dropping this store makes that authority unavailable.

use crate::store::{
    without_lifecycle, ActionSummary, ApiStore, ApprovalDecision, ApprovalRecord, AuthorizationEntry,
    AuthorizationInsert, AuthorizationRevoked, DecideOutcome, DeliveryResult, DeliveryStatus, IdemBegin,
    KeyRecord, StoreResult, StoredResponse, TrafficFilter, TrafficRecord, TransitionFilter, TransitionRecord,
    WebhookDelivery,
};
use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use crawlx_core::counters::ActionStatus;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ActionJournal, ActionRecord, LedgerRepo};
use crawlx_core::traffic::TrustLane;
use crawlx_core::{
    ApprovalId, AuthorizationRecordId, CrawlRunId, StateId, StoreError, TenantId, Timestamp, TransitionId,
};
use crawlx_policy::AuthorizationRecord;
use crawlx_storage::memory::{HeadResponseAuthorizer, MemoryTransition};
use crawlx_storage::{CoverageRow, MemoryStore, TenantEngine};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Weak};
use uuid::Uuid;

const IDEMPOTENCY_RETENTION_HOURS: i64 = 24;

enum IdemState {
    InProgress,
    Done(StoredResponse),
}

struct IdemRow {
    hash: Digest,
    state: IdemState,
    created: Timestamp,
    /// The run an in-progress claim announced ([`ApiStore::idem_link_run`]).
    run: Option<CrawlRunId>,
}

/// One recorded audit event (memory mirror of `audit_events`).
#[derive(Clone, PartialEq, Debug)]
pub struct AuditEntry {
    /// Tenant the event is attributed to.
    pub tenant: TenantId,
    /// Run the event concerns; `None` for tenant-level events.
    pub run: Option<CrawlRunId>,
    /// Who acted, formatted `api_key:<key_id>`.
    pub actor: String,
    /// Event name (for example `approval.approved`).
    pub event: String,
    /// Event details as JSON (ids and labels only, never secrets).
    pub subject: Value,
}

/// One stored authorization record (memory mirror of `authorization_records`).
struct AuthzRow {
    tenant: TenantId,
    /// The record with its lifecycle state (`verified_at`, `revoked_at`, `revoked_reason`).
    record: AuthorizationRecord,
    verification: Option<Value>,
}

impl AuthzRow {
    fn entry(&self) -> StoreResult<AuthorizationEntry> {
        Ok(AuthorizationEntry {
            // the digest excludes lifecycle state, so it is the digest stored at creation
            body_digest: self
                .record
                .body_digest()
                .map_err(|e| StoreError::Serialization(e.to_string()))?,
            record: self.record.clone(),
            verification: self.verification.clone(),
        })
    }
}

#[derive(Default)]
struct Inner {
    keys: HashMap<String, KeyRecord>,
    idem: HashMap<(TenantId, String), IdemRow>,
    audit: Vec<AuditEntry>,
    runs: Vec<(TenantId, CrawlRunId)>,
    shadows: BTreeSet<CrawlRunId>,
    engines: HashMap<TenantId, TenantEngine>,
    authz: HashMap<AuthorizationRecordId, AuthzRow>,
    run_digests: HashMap<CrawlRunId, Digest>,
    webhook_runs: BTreeSet<CrawlRunId>,
    deliveries: Vec<WebhookDelivery>,
}

struct MemoryHeadResponseAuthorizer {
    inner: Weak<Mutex<Inner>>,
}

#[async_trait]
impl HeadResponseAuthorizer for MemoryHeadResponseAuthorizer {
    async fn authorize(
        &self,
        run: CrawlRunId,
        tenant: TenantId,
        record: AuthorizationRecordId,
        now: Timestamp,
    ) -> StoreResult<()> {
        let inner = self.inner.upgrade().ok_or_else(|| {
            StoreError::AccessDenied("HEAD response authorization source is unavailable".to_owned())
        })?;
        let inner = inner.lock();
        let row = inner.authz.get(&record).ok_or_else(|| {
            StoreError::AccessDenied("HEAD response authorization record is missing".to_owned())
        })?;
        if row.tenant != tenant
            || row.record.tenant != tenant
            || row.record.id != record
            || row.record.valid_from > now
            || row.record.valid_to <= now
            || row.record.revoked_at.is_some()
            || row.record.verified_at.is_none()
        {
            return Err(StoreError::AccessDenied(
                "HEAD response authorization record is not active and verified".to_owned(),
            ));
        }
        if let Some(bound) = inner.run_digests.get(&run) {
            let current = row
                .record
                .body_digest()
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            if *bound != current {
                return Err(StoreError::AccessDenied(
                    "HEAD response authorization body binding changed".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// In-memory [`ApiStore`].
pub struct MemoryApiStore {
    inner: Arc<Mutex<Inner>>,
    store: Arc<MemoryStore>,
}

impl MemoryApiStore {
    /// Store over `store` (actions and traffic are read from it).
    #[must_use]
    pub fn new(store: Arc<MemoryStore>) -> Self {
        let inner = Arc::new(Mutex::new(Inner::default()));
        store.set_head_response_authorizer(Arc::new(MemoryHeadResponseAuthorizer {
            inner: Arc::downgrade(&inner),
        }));
        Self { inner, store }
    }

    /// Seed an unbound API fixture. Worker requests use the shared approval repository.
    pub fn add_approval(&self, approval: ApprovalRecord) {
        self.store.insert_approval_record(approval);
    }

    /// Mark an unbound fixture consumed. Bound worker requests require fenced consumption.
    pub fn consume_approval(&self, id: ApprovalId, at: Timestamp) {
        self.store.consume_approval_fixture(id, at);
    }

    /// Seed an authorization record exactly as given (lifecycle fields included): the test
    /// shortcut around `POST /v1/authorizations`.
    pub fn add_authorization(&self, record: AuthorizationRecord) {
        self.inner.lock().authz.insert(
            record.id,
            AuthzRow {
                tenant: record.tenant,
                record,
                verification: None,
            },
        );
    }

    /// Whether `run` was tagged `run_kind = 'shadow'`.
    #[must_use]
    pub fn is_shadow(&self, run: CrawlRunId) -> bool {
        self.inner.lock().shadows.contains(&run)
    }

    /// Set the tenant engine flag (what `crawlx admin engine` does on PostgreSQL).
    pub fn set_tenant_engine(&self, tenant: TenantId, engine: TenantEngine) {
        self.inner.lock().engines.insert(tenant, engine);
    }

    /// Audit events written so far.
    #[must_use]
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.inner.lock().audit.clone()
    }

    /// Every webhook delivery row.
    #[must_use]
    pub fn deliveries(&self) -> Vec<WebhookDelivery> {
        self.inner.lock().deliveries.clone()
    }

    /// Erasure: drop everything this store holds about `run`.
    #[must_use]
    pub fn purge_run(&self, run: CrawlRunId) -> u64 {
        let mut g = self.inner.lock();
        let mut n = 0u64;
        n += self.store.purge_approval_records(run);
        let before = g.deliveries.len();
        g.deliveries.retain(|d| d.run != run);
        n += (before - g.deliveries.len()) as u64;
        g.webhook_runs.remove(&run);
        g.runs.retain(|(_, r)| *r != run);
        g.idem.retain(|_, row| match &row.state {
            IdemState::Done(r) => r.run_id != Some(run),
            IdemState::InProgress => true,
        });
        n
    }

    fn lane_of(rec: &ActionRecord) -> TrustLane {
        rec.lane
            .or_else(|| rec.fidelity.map(crawlx_core::traffic::Fidelity::lane))
            .unwrap_or(TrustLane::Diagnostic)
    }
}

/// In-memory counterpart of the `trusted_reachable_states` view (migration 0008): a state
/// with no incoming transition is a root; other states are reachable only through
/// trusted-lane transitions from reachable states.
struct TrustedReachable {
    afters: BTreeSet<StateId>,
    closure: BTreeSet<StateId>,
}

impl TrustedReachable {
    fn new(transitions: &[MemoryTransition]) -> Self {
        let afters: BTreeSet<StateId> = transitions.iter().filter_map(|t| t.after).collect();
        let mut closure: BTreeSet<StateId> = transitions
            .iter()
            .map(|t| t.before)
            .filter(|s| !afters.contains(s))
            .collect();
        loop {
            let before = closure.len();
            for t in transitions.iter().filter(|t| t.lane == TrustLane::TrustedUi) {
                if let Some(after) = t.after {
                    if closure.contains(&t.before) {
                        closure.insert(after);
                    }
                }
            }
            if closure.len() == before {
                break;
            }
        }
        Self { afters, closure }
    }

    fn contains(&self, state: StateId) -> bool {
        !self.afters.contains(&state) || self.closure.contains(&state)
    }
}

fn summary_of(rec: &ActionRecord) -> ActionSummary {
    ActionSummary {
        id: rec.id,
        seq: rec.seq,
        kind: rec.key.action_kind.as_str().to_owned(),
        status: rec.status,
        lane: rec.lane,
        fidelity: rec.fidelity.map(|f| f.as_str().to_owned()),
        strategy: rec.strategy.clone(),
        strategy_version: rec.strategy_version,
        context_id: rec.key.id().to_string(),
        risk_class: None,
        safety_verdict: None,
    }
}

fn headers_value(h: &[(String, String)]) -> Value {
    let mut m = serde_json::Map::new();
    for (k, v) in h {
        m.insert(k.clone(), Value::String(v.clone()));
    }
    Value::Object(m)
}

#[async_trait]
impl ApiStore for MemoryApiStore {
    async fn key_by_prefix(&self, prefix: &str) -> StoreResult<Option<KeyRecord>> {
        Ok(self.inner.lock().keys.get(prefix).cloned())
    }

    async fn key_insert(&self, key: &KeyRecord, _tenant_name: &str) -> StoreResult<()> {
        self.inner
            .lock()
            .keys
            .entry(key.prefix.clone())
            .or_insert_with(|| key.clone());
        Ok(())
    }

    async fn key_touch(&self, _key_id: Uuid, _at: Timestamp) -> StoreResult<()> {
        Ok(())
    }

    async fn idem_begin(
        &self,
        tenant: TenantId,
        key: &str,
        request_hash: Digest,
        now: Timestamp,
    ) -> StoreResult<IdemBegin> {
        let mut g = self.inner.lock();
        let k = (tenant, key.to_owned());
        if let Some(row) = g.idem.get(&k) {
            if row.created + ChronoDuration::hours(IDEMPOTENCY_RETENTION_HOURS) > now {
                if row.hash != request_hash {
                    return Ok(IdemBegin::Mismatch);
                }
                return Ok(match &row.state {
                    IdemState::InProgress => IdemBegin::InProgress,
                    IdemState::Done(r) => IdemBegin::Replay(r.clone()),
                });
            }
        }
        g.idem.insert(
            k,
            IdemRow {
                hash: request_hash,
                state: IdemState::InProgress,
                created: now,
                run: None,
            },
        );
        Ok(IdemBegin::Started)
    }

    async fn idem_complete(&self, tenant: TenantId, key: &str, response: &StoredResponse) -> StoreResult<()> {
        let mut g = self.inner.lock();
        match g.idem.get_mut(&(tenant, key.to_owned())) {
            Some(row) => {
                row.state = IdemState::Done(response.clone());
                Ok(())
            }
            None => Err(StoreError::NotFound {
                entity: "idempotency_key",
                id: key.to_owned(),
            }),
        }
    }

    async fn idem_release(&self, tenant: TenantId, key: &str) -> StoreResult<()> {
        let mut g = self.inner.lock();
        let k = (tenant, key.to_owned());
        if matches!(g.idem.get(&k).map(|r| &r.state), Some(IdemState::InProgress)) {
            g.idem.remove(&k);
        }
        Ok(())
    }

    async fn idem_link_run(&self, tenant: TenantId, key: &str, run: CrawlRunId) -> StoreResult<()> {
        if let Some(row) = self.inner.lock().idem.get_mut(&(tenant, key.to_owned())) {
            if matches!(row.state, IdemState::InProgress) {
                row.run = Some(run);
            }
        }
        Ok(())
    }

    async fn idem_run(&self, tenant: TenantId, key: &str) -> StoreResult<Option<CrawlRunId>> {
        Ok(self
            .inner
            .lock()
            .idem
            .get(&(tenant, key.to_owned()))
            .and_then(|row| match &row.state {
                IdemState::InProgress => row.run,
                IdemState::Done(r) => r.run_id,
            }))
    }

    async fn approvals_list(&self, run: CrawlRunId) -> StoreResult<Vec<ApprovalRecord>> {
        Ok(self.store.approval_records(run))
    }

    async fn approval_get(&self, run: CrawlRunId, id: ApprovalId) -> StoreResult<Option<ApprovalRecord>> {
        Ok(self
            .store
            .approval_records(run)
            .into_iter()
            .find(|record| record.id == id))
    }

    async fn approval_decide(
        &self,
        run: CrawlRunId,
        id: ApprovalId,
        decision: ApprovalDecision,
        decided_by: Uuid,
        reason: Option<&str>,
        _now: Timestamp,
    ) -> StoreResult<DecideOutcome> {
        self.store
            .decide_approval_record(run, id, decision, decided_by, reason)
    }

    async fn transitions_list(
        &self,
        run: CrawlRunId,
        filter: &TransitionFilter,
    ) -> StoreResult<Vec<TransitionRecord>> {
        let actions = ActionJournal::list(self.store.as_ref(), run, None).await?;
        let transitions: BTreeMap<_, _> = self
            .store
            .transitions(run)
            .into_iter()
            .map(|transition| (transition.action, transition))
            .collect();
        let mut out: Vec<TransitionRecord> = actions
            .iter()
            .filter(|a| {
                matches!(
                    a.status,
                    ActionStatus::Succeeded | ActionStatus::Failed | ActionStatus::Reconciled
                )
            })
            .filter_map(|a| {
                let before = a.before_state?;
                Some(TransitionRecord {
                    id: TransitionId(a.id.0),
                    session: a.session,
                    role: a.key.principal.0.clone(),
                    before,
                    after: transitions.get(&a.id).and_then(|transition| transition.after),
                    network_epoch: transitions
                        .get(&a.id)
                        .and_then(|transition| transition.network_epoch),
                    lane: Self::lane_of(a),
                    settle: None,
                    action: summary_of(a),
                    created_at: a.finished_at.unwrap_or(a.proposed_at),
                })
            })
            .filter(|t| filter.session.is_none_or(|s| t.session == s))
            .filter(|t| filter.role.as_ref().is_none_or(|r| &t.role == r))
            .filter(|t| filter.lane.is_none_or(|l| t.lane == l))
            .filter(|t| filter.status.is_none_or(|s| t.action.status == s))
            .filter(|t| filter.from_state.is_none_or(|s| t.before == s))
            .filter(|t| filter.to_state.is_none_or(|s| t.after == Some(s)))
            .collect();
        out.sort_by_key(|t| t.id);
        Ok(out)
    }

    async fn traffic_list(&self, run: CrawlRunId, filter: &TrafficFilter) -> StoreResult<Vec<TrafficRecord>> {
        let actions = ActionJournal::list(self.store.as_ref(), run, None).await?;
        let mut out = Vec::new();
        for a in &actions {
            let lane = Self::lane_of(a);
            if filter.lane.is_some_and(|l| l != lane) {
                continue;
            }
            if filter.role.as_ref().is_some_and(|r| r != &a.key.principal.0) {
                continue;
            }
            for e in self.store.traffic(a.id) {
                if filter.epoch.is_some_and(|ep| e.epoch_id != Some(ep)) {
                    continue;
                }
                if filter.origin.is_some_and(|o| e.origin != o) {
                    continue;
                }
                out.push(TrafficRecord {
                    id: format!("{}:{:010}", a.id, e.seq),
                    epoch_id: e.epoch_id,
                    action: Some(a.id),
                    lane,
                    role: Some(a.key.principal.0.clone()),
                    origin: e.origin,
                    method: Some(e.method.clone()),
                    url: e.url.clone(),
                    status: e.status,
                    third_party: e.third_party,
                    late: e.late,
                    request_headers: headers_value(&e.request_headers),
                    response_headers: headers_value(&e.response_headers),
                    response_body: e.response_body.clone(),
                    occurred_at: e.started_at,
                });
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn coverage(&self, run: CrawlRunId) -> StoreResult<Vec<CoverageRow>> {
        let ledger = LedgerRepo::list(self.store.as_ref(), run).await?;
        let actions = ActionJournal::list(self.store.as_ref(), run, None).await?;
        let reachable = TrustedReachable::new(&self.store.transitions(run));
        let denied = self.store.denied_contexts(run);
        let mut rows = Vec::with_capacity(ledger.len());
        for l in ledger {
            let (mut reachable_trusted, mut unknown) = (0u32, 0u32);
            for a in actions.iter().filter(|a| a.key == l.key) {
                match a.status {
                    ActionStatus::Unknown => unknown = unknown.saturating_add(1),
                    ActionStatus::Succeeded
                        if Self::lane_of(a) == TrustLane::TrustedUi
                            && a.before_state.is_some_and(|s| reachable.contains(s)) =>
                    {
                        reachable_trusted = reachable_trusted.saturating_add(1);
                    }
                    _ => {}
                }
            }
            let trusted_exercised = reachable_trusted.min(l.trusted_exercised);
            let denied_count = denied.get(&l.key.id()).copied().unwrap_or(0);
            rows.push(CoverageRow {
                key: l.key,
                trusted_exercised,
                trusted_unreachable: l.trusted_exercised - trusted_exercised,
                diagnostic_exercised: l.diagnostic_exercised,
                failures: l.failures,
                denied: denied_count,
                unknown,
                first_seen: l.first_seen,
                last_exercised: l.last_exercised,
            });
        }
        Ok(rows)
    }

    async fn active_run_count(&self, tenant: TenantId) -> StoreResult<u64> {
        let active = self.active_runs(tenant).await?;
        Ok(u64::try_from(active.len()).unwrap_or(u64::MAX))
    }

    async fn active_runs(&self, tenant: TenantId) -> StoreResult<Vec<CrawlRunId>> {
        let runs: Vec<CrawlRunId> = self
            .inner
            .lock()
            .runs
            .iter()
            .filter(|(t, _)| *t == tenant)
            .map(|(_, r)| *r)
            .collect();
        let mut active = Vec::new();
        for r in runs {
            if let Ok(run) = crawlx_core::repo::RunRepo::get(self.store.as_ref(), r).await {
                if !run.status.is_terminal() {
                    active.push(r);
                }
            }
        }
        Ok(active)
    }

    async fn run_created(&self, tenant: TenantId, run: CrawlRunId) -> StoreResult<()> {
        self.inner.lock().runs.push((tenant, run));
        Ok(())
    }

    async fn shadow_tag(&self, run: CrawlRunId) -> StoreResult<()> {
        self.inner.lock().shadows.insert(run);
        Ok(())
    }

    async fn tenant_engine(&self, tenant: TenantId) -> StoreResult<TenantEngine> {
        Ok(self
            .inner
            .lock()
            .engines
            .get(&tenant)
            .copied()
            .unwrap_or_default())
    }

    async fn authorization_get(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> StoreResult<Option<AuthorizationRecord>> {
        Ok(self
            .inner
            .lock()
            .authz
            .get(&id)
            .filter(|row| row.tenant == tenant)
            .map(|row| row.record.clone()))
    }

    async fn authorization_entry(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> StoreResult<Option<AuthorizationEntry>> {
        self.inner
            .lock()
            .authz
            .get(&id)
            .filter(|row| row.tenant == tenant)
            .map(AuthzRow::entry)
            .transpose()
    }

    async fn authorization_create(
        &self,
        tenant: TenantId,
        _created_by: Uuid,
        record: &AuthorizationRecord,
        verification: &Value,
        verified_at: Timestamp,
    ) -> StoreResult<AuthorizationInsert> {
        let stored = AuthorizationRecord {
            verified_at: Some(verified_at),
            ..without_lifecycle(record)
        };
        let digest = record
            .body_digest()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        let mut inner = self.inner.lock();
        if let Some(existing) = inner.authz.get(&record.id) {
            let same = existing.tenant == tenant && existing.entry()?.body_digest == digest;
            return Ok(if same {
                AuthorizationInsert::Replayed
            } else {
                AuthorizationInsert::Taken
            });
        }
        inner.authz.insert(
            record.id,
            AuthzRow {
                tenant,
                record: stored,
                verification: Some(verification.clone()),
            },
        );
        Ok(AuthorizationInsert::Created)
    }

    async fn authorization_revoke(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        _by: Uuid,
        reason: Option<&str>,
        now: Timestamp,
    ) -> StoreResult<Option<AuthorizationRevoked>> {
        let mut inner = self.inner.lock();
        let Some(row) = inner.authz.get_mut(&id).filter(|row| row.tenant == tenant) else {
            return Ok(None);
        };
        let first = row.record.revoked_at.is_none();
        if first {
            row.record.revoked_at = Some(now);
            row.record.revoked_reason = reason.map(str::to_owned);
        }
        Ok(Some(AuthorizationRevoked {
            entry: row.entry()?,
            first,
        }))
    }

    async fn authorization_mark_verified(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        verification: &Value,
        now: Timestamp,
    ) -> StoreResult<Option<AuthorizationEntry>> {
        let mut inner = self.inner.lock();
        let Some(row) = inner.authz.get_mut(&id).filter(|row| row.tenant == tenant) else {
            return Ok(None);
        };
        row.record.verified_at = Some(now);
        row.verification = Some(verification.clone());
        row.entry().map(Some)
    }

    async fn authorization_bind_run(&self, run: CrawlRunId, body_digest: Digest) -> StoreResult<()> {
        // like the SQL `UPDATE crawl_runs`: the run must exist
        crawlx_core::repo::RunRepo::get(self.store.as_ref(), run).await?;
        self.inner.lock().run_digests.insert(run, body_digest);
        Ok(())
    }

    async fn authorization_run_digest(&self, run: CrawlRunId) -> StoreResult<Option<Digest>> {
        crawlx_core::repo::RunRepo::get(self.store.as_ref(), run).await?;
        Ok(self.inner.lock().run_digests.get(&run).copied())
    }

    async fn audit_append(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        actor: &str,
        event: &str,
        subject: Value,
    ) -> StoreResult<()> {
        self.inner.lock().audit.push(AuditEntry {
            tenant,
            run,
            actor: actor.to_owned(),
            event: event.to_owned(),
            subject,
        });
        Ok(())
    }

    async fn webhook_runs(&self) -> StoreResult<Vec<CrawlRunId>> {
        Ok(self.inner.lock().webhook_runs.iter().copied().collect())
    }

    async fn webhook_watch(&self, run: CrawlRunId) -> StoreResult<()> {
        self.inner.lock().webhook_runs.insert(run);
        Ok(())
    }

    async fn webhook_cursor(&self, run: CrawlRunId) -> StoreResult<u64> {
        Ok(self
            .inner
            .lock()
            .deliveries
            .iter()
            .filter(|d| d.run == run)
            .map(|d| d.event_seq)
            .max()
            .unwrap_or(0))
    }

    async fn webhook_enqueue(&self, delivery: &WebhookDelivery) -> StoreResult<bool> {
        let mut g = self.inner.lock();
        if g.deliveries
            .iter()
            .any(|d| d.run == delivery.run && d.event_seq == delivery.event_seq && d.url == delivery.url)
        {
            return Ok(false);
        }
        g.deliveries.push(delivery.clone());
        Ok(true)
    }

    async fn webhook_claim_due(
        &self,
        now: Timestamp,
        limit: u32,
        lease_secs: u32,
    ) -> StoreResult<Vec<WebhookDelivery>> {
        let mut g = self.inner.lock();
        let mut idx: Vec<usize> = g
            .deliveries
            .iter()
            .enumerate()
            .filter(|(_, d)| d.status == DeliveryStatus::Pending && d.next_attempt_at <= now)
            .map(|(i, _)| i)
            .collect();
        idx.sort_by(|a, b| {
            let (x, y) = (&g.deliveries[*a], &g.deliveries[*b]);
            (x.next_attempt_at, x.id).cmp(&(y.next_attempt_at, y.id))
        });
        idx.truncate(limit as usize);
        let mut out = Vec::with_capacity(idx.len());
        for i in idx {
            let d = &mut g.deliveries[i];
            out.push(d.clone());
            d.next_attempt_at = now + ChronoDuration::seconds(i64::from(lease_secs));
        }
        Ok(out)
    }

    async fn webhook_record(&self, id: Uuid, result: &DeliveryResult) -> StoreResult<()> {
        let mut g = self.inner.lock();
        let Some(d) = g.deliveries.iter_mut().find(|d| d.id == id) else {
            return Err(StoreError::NotFound {
                entity: "webhook_delivery",
                id: id.to_string(),
            });
        };
        d.attempts += 1;
        match result {
            DeliveryResult::Delivered { status, at } => {
                d.status = DeliveryStatus::Delivered;
                d.delivered_at = Some(*at);
                d.last_status = Some(*status);
                d.last_error = None;
            }
            DeliveryResult::Retry {
                status,
                error,
                next_attempt_at,
            } => {
                d.next_attempt_at = *next_attempt_at;
                d.last_status = *status;
                d.last_error = Some(error.clone());
            }
            DeliveryResult::Dead { status, error } => {
                d.status = DeliveryStatus::Dead;
                d.last_status = *status;
                d.last_error = Some(error.clone());
            }
        }
        Ok(())
    }

    async fn webhook_dead_count(&self, run: CrawlRunId) -> StoreResult<u64> {
        Ok(self
            .inner
            .lock()
            .deliveries
            .iter()
            .filter(|d| d.run == run && d.status == DeliveryStatus::Dead)
            .count() as u64)
    }

    async fn webhook_list(&self, run: CrawlRunId) -> StoreResult<Vec<WebhookDelivery>> {
        let mut v: Vec<WebhookDelivery> = self
            .inner
            .lock()
            .deliveries
            .iter()
            .filter(|d| d.run == run)
            .cloned()
            .collect();
        v.sort_by_key(|d| (d.event_seq, d.id));
        Ok(v)
    }
}

/// Approval summary helper for seeding (`role`, `route_template`, ...).
#[must_use]
pub fn approval_summary(role: &str, route_template: &str, action_kind: &str) -> Value {
    json!({
        "role": role,
        "route_template": route_template,
        "action_kind": action_kind,
        "resource_context": "own",
        "input_class": "none",
    })
}
