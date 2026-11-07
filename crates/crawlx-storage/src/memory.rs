//! In-memory implementations of every repository trait plus [`LeaseRepo`], for
//! worker, strategy and scheduler tests.
//!
//! [`MemoryStore`] enforces the same rules as the PostgreSQL implementation:
//! the `actions.status` machine, fencing tokens, the round-robin barrier,
//! idempotent state/cluster writes, one `crawl_events.seq` space per run. It is
//! not a performance model. Time comes from an injected [`Clock`], so tests drive
//! lease expiry with `ManualClock`.
//!
//! [`InMemoryJournal`] is a thin `ActionJournal`-only handle over a store, for
//! tests that only care about the T1/T2 journal.

use crate::admin::AdmissionMode;
use crate::checkpoint_crypto::{CheckpointCryptoError, CheckpointKeys, MemoryCheckpointKeys};
use crate::leases::{
    ActiveRun, FrontierReap, LeaseRepo, ReapReport, SessionLease, DEFAULT_SESSION_TTL, DEFAULT_URL_BATCH_TTL,
};
use crate::repos::{pick_successor, split_event};
use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{ActionStatus, PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ElementIdentityHash};
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::{
    ActionJournal, ActionRecord, CheckpointRecord, CheckpointRepo, ClusterSplitRecord, CrawlRun,
    CrawlSession, DiscoveryOutcome, EdgeRecord, EdgeStore, EventRepo, FrontierEntry, FrontierRepo,
    FrontierStateCounts, FrontierStatus, IdentityAlias, IdentityAliasRepo, JournalOutcomes, KnownPage,
    LedgerRepo, LedgerRow, ModelDecisionRecord, ModelDecisionRepo, NewState, OutcomeRecord, PageRecord,
    PageRepo, Reconciliation, RunEvent, RunRepo, SafetyAudit, SessionStatus, SplitApplied, StateRepo,
};
use crawlx_core::safety::{SafetyDecision, SafetyVerdict};
use crawlx_core::state::StateSignature;
use crawlx_core::traffic::{TrafficEvent, TrustLane};
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{
    ActionContextId, ActionId, CheckpointId, Clock, CrawlRunId, EdgeId, NetworkEpochId, SessionId,
    StateClusterId, StateId, StoreError, SystemClock, TenantId, Timestamp, TraceId, WorkerId,
};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

#[path = "adaptive_selectors.rs"]
pub mod adaptive_selectors;
#[path = "request_memory.rs"]
mod request_memory;

#[derive(Clone)]
struct SessionRow {
    s: CrawlSession,
    owner: Option<WorkerId>,
    token: Option<i64>,
    expires: Option<Timestamp>,
    render: bool,
}

#[derive(Clone)]
struct FrontierRow {
    e: FrontierEntry,
    key: Digest,
    strategy_score: u32,
    owner: Option<WorkerId>,
    token: Option<i64>,
    expires: Option<Timestamp>,
    next_attempt_at: Timestamp,
}

#[derive(Clone)]
struct ActionRow {
    rec: ActionRecord,
    hold: Hold,
    dataset_page: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hold {
    None,
    Denied,
    AwaitingApproval,
}

struct ClusterRow {
    id: StateClusterId,
    run: CrawlRunId,
    signature: StateSignature,
    members: u32,
    /// Starts at 1; a split creates successors at `version + 1`.
    version: u32,
    /// Set by a split; superseded clusters are not listed and take no new members.
    superseded: bool,
}

/// Mirror of one `transitions` row (the trail), written by T2 when the
/// action had a `before_state`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct MemoryTransition {
    /// The action that caused the transition (unique per action).
    pub action: ActionId,
    /// Session the action ran in.
    pub session: SessionId,
    /// State observed before the action.
    pub before: StateId,
    /// State observed after the action, when one was captured.
    pub after: Option<StateId>,
    /// Network epoch of the action's receipt.
    pub network_epoch: Option<NetworkEpochId>,
    /// Lane derived from the receipt fidelity.
    pub lane: TrustLane,
    /// Whether the settle after the action timed out.
    pub settle_timeout: bool,
}

/// Mirror of one `network_epochs` row, written by T2 when the action had a receipt.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct MemoryNetworkEpoch {
    /// Epoch id from the executor receipt.
    pub id: NetworkEpochId,
    /// Session the epoch belongs to.
    pub session: SessionId,
    /// Action the epoch is attributed to.
    pub action: ActionId,
    /// Lane of the action.
    pub lane: TrustLane,
    /// Traffic events attributed to the epoch.
    pub request_count: u64,
    /// Whether the settle timed out.
    pub settle_timeout: bool,
}

#[derive(Default)]
struct Inner {
    checkpoint_keys: Option<Arc<dyn CheckpointKeys>>,
    runs: HashMap<CrawlRunId, CrawlRun>,
    replay_specs: HashMap<CrawlRunId, serde_json::Value>,
    idempotency: HashMap<(TenantId, String), (CrawlRunId, Digest)>,
    sessions: BTreeMap<SessionId, SessionRow>,
    frontier: Vec<FrontierRow>,
    requests: request_memory::RequestState,
    dataset: crate::dataset::DatasetState,
    adaptive_selectors: BTreeMap<String, adaptive_selectors::StoredDescriptor>,
    pages: Vec<PageRecord>,
    page_captures: BTreeMap<(CrawlRunId, i64), PageRecord>,
    actions: BTreeMap<ActionId, ActionRow>,
    action_order: Vec<ActionId>,
    session_seq: HashMap<SessionId, u64>,
    states: Vec<NewState>,
    state_runs: HashMap<StateId, CrawlRunId>,
    clusters: Vec<ClusterRow>,
    edges: Vec<EdgeRecord>,
    ledger: HashMap<(CrawlRunId, ActionContextId), LedgerRow>,
    events: HashMap<CrawlRunId, Vec<RunEvent>>,
    safety: Vec<(CrawlRunId, SessionId, SafetyVerdict, String)>,
    traffic: Vec<(ActionId, TrafficEvent)>,
    transitions: Vec<(CrawlRunId, MemoryTransition)>,
    network_epochs: Vec<(CrawlRunId, MemoryNetworkEpoch)>,
    checkpoints: Vec<CheckpointRecord>,
    model_decisions: Vec<ModelDecisionRecord>,
    identity_aliases: Vec<(CrawlRunId, IdentityAlias)>,
    fence: i64,
    next_frontier_id: i64,
    next_dataset_action: i64,
}

/// All repositories in process memory.
pub struct MemoryStore {
    inner: Mutex<Inner>,
    clock: Arc<dyn Clock>,
    session_ttl: Duration,
    url_ttl: Duration,
    admission: Mutex<AdmissionMode>,
    dataset_delivery: Mutex<Option<Arc<crate::DeliveryBuffer>>>,
    pub(crate) archives: Mutex<crate::archive_catalog::ArchiveState>,
    pub(crate) worker_registry: Mutex<crate::admin::WorkerRegistryState>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

fn nf(entity: &'static str, id: impl std::fmt::Display) -> StoreError {
    StoreError::NotFound {
        entity,
        id: id.to_string(),
    }
}

fn chrono_dur(d: Duration) -> ChronoDuration {
    ChronoDuration::milliseconds(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl MemoryStore {
    /// Store on the wall clock.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// Store on an injected clock (tests use `ManualClock`).
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            clock,
            session_ttl: DEFAULT_SESSION_TTL,
            url_ttl: DEFAULT_URL_BATCH_TTL,
            admission: Mutex::new(AdmissionMode::Open),
            dataset_delivery: Mutex::new(None),
            archives: Mutex::new(crate::archive_catalog::ArchiveState::default()),
            worker_registry: Mutex::new(crate::admin::WorkerRegistryState::default()),
        }
    }

    /// Retrieve this store's shared, process-local checkpoint custody.
    ///
    /// Reopening worker wrappers over the same store preserves decryption access.
    /// A distinct store receives an independent key. Initialization happens only
    /// on a successful first request; an entropy failure is not cached.
    ///
    /// # Errors
    /// Returns [`CheckpointCryptoError::Entropy`] if initial OS entropy is unavailable.
    pub fn checkpoint_keys(&self) -> Result<Arc<dyn CheckpointKeys>, CheckpointCryptoError> {
        let mut inner = self.inner.lock();
        if let Some(keys) = &inner.checkpoint_keys {
            return Ok(Arc::clone(keys));
        }
        let keys: Arc<dyn CheckpointKeys> = Arc::new(MemoryCheckpointKeys::new()?);
        inner.checkpoint_keys = Some(Arc::clone(&keys));
        Ok(keys)
    }

    pub(crate) fn worker_registry_now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Attach the same volatile authority used by the artifact sink.
    pub fn set_dataset_delivery(&self, buffer: Arc<crate::DeliveryBuffer>) {
        *self.dataset_delivery.lock() = Some(buffer);
    }

    async fn durable_run(&self, run: &CrawlRun) -> Result<CrawlRun, StoreError> {
        if run.config.fetch.has_literal_secrets() {
            let buffer = self.dataset_delivery.lock().clone().ok_or_else(|| {
                StoreError::RetentionDenied("literal request controls require volatile storage".into())
            })?;
            let bytes = serde_json::to_vec(&run.config.fetch)?;
            buffer
                .insert(
                    run.tenant,
                    run.id,
                    i64::MIN,
                    &format!("_fetch_controls:{}", run.config_digest.to_hex()),
                    "application/json",
                    &bytes,
                )
                .await?;
        }
        let mut stored = run.clone();
        stored.config.fetch = run.config.fetch.durable();
        Ok(stored)
    }

    /// Flip `scheduler.admission` (what `crawlx admin freeze` does on PostgreSQL).
    pub fn set_admission(&self, mode: AdmissionMode) {
        *self.admission.lock() = mode;
    }

    /// Override the lease TTLs.
    #[must_use]
    pub fn with_ttls(mut self, session: Duration, url_batch: Duration) -> Self {
        self.session_ttl = session;
        self.url_ttl = url_batch;
        self
    }

    /// Traffic written by T2 for `action`, in `seq` order.
    #[must_use]
    pub fn traffic(&self, action: ActionId) -> Vec<TrafficEvent> {
        let mut v: Vec<TrafficEvent> = self
            .inner
            .lock()
            .traffic
            .iter()
            .filter(|(a, _)| *a == action)
            .map(|(_, t)| t.clone())
            .collect();
        v.sort_by_key(|t| t.seq);
        v
    }

    /// Every traffic event of `run` with the action it was journaled under, in capture
    /// order (`traffic_events` of the trail; the memory mirror keeps the event's own
    /// `epoch_id`/`unattributed_reason`, the receipt epoch is on the action's epoch row).
    #[must_use]
    pub fn traffic_of_run(&self, run: CrawlRunId) -> Vec<(ActionId, TrafficEvent)> {
        let g = self.inner.lock();
        g.traffic
            .iter()
            .filter(|(a, _)| g.actions.get(a).is_some_and(|row| row.rec.run == run))
            .cloned()
            .collect()
    }
    pub(crate) fn archive_run_active(&self, run: CrawlRunId) -> bool {
        self.inner
            .lock()
            .runs
            .get(&run)
            .is_some_and(|row| !row.status.is_terminal())
    }

    pub(crate) fn archive_traffic_keyset(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        after: u64,
        limit: u32,
    ) -> Result<Vec<crawlx_core::archive_catalog::ArchiveTrafficV1>, StoreError> {
        if !(1..=64).contains(&limit) {
            return Err(StoreError::Conflict(
                "archive traffic page limit must be 1..64".into(),
            ));
        }
        let state = self.inner.lock();
        let source = state.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
        if source.tenant != tenant || source.config.retention.mode == crawlx_core::config::RetentionMode::Zdr
        {
            return Err(StoreError::AccessDenied(
                "archive traffic source is not retained tenant content".into(),
            ));
        }
        let mut rows = Vec::with_capacity(usize::try_from(limit).unwrap_or(64));
        for (index, (action, event)) in state.traffic.iter().enumerate() {
            let ordinal = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| StoreError::Conflict("archive traffic ordinal overflow".into()))?;
            if ordinal <= after || !state.actions.get(action).is_some_and(|row| row.rec.run == run) {
                continue;
            }
            rows.push(crawlx_core::archive_catalog::ArchiveTrafficV1::new(
                ordinal,
                Some(event.url.clone()),
                event.started_at,
                event.request_body.clone(),
                event.response_body.clone(),
            ));
            if rows.len() >= usize::try_from(limit).unwrap_or(64) {
                break;
            }
        }
        Ok(rows)
    }

    /// Ids of every `safety_decisions` row of `run` (adjudications and audit-only verdicts).
    #[must_use]
    pub fn safety_decision_ids(&self, run: CrawlRunId) -> Vec<crawlx_core::SafetyDecisionId> {
        self.inner
            .lock()
            .safety
            .iter()
            .filter(|(r, ..)| *r == run)
            .map(|(_, _, v, _)| v.decision_id)
            .collect()
    }

    /// Denied journal proposals per coverage key, excluding pending approvals.
    #[must_use]
    pub fn denied_contexts(&self, run: CrawlRunId) -> BTreeMap<crawlx_core::ActionContextId, u32> {
        let g = self.inner.lock();
        let mut counts = BTreeMap::new();
        for action in g.actions.values() {
            if action.rec.run == run && matches!(action.hold, Hold::Denied) {
                let count = counts.entry(action.rec.key.id()).or_insert(0_u32);
                *count = count.saturating_add(1);
            }
        }
        counts
    }

    /// Transitions written by T2 for `run`, in write order (the trail).
    #[must_use]
    pub fn transitions(&self, run: CrawlRunId) -> Vec<MemoryTransition> {
        self.inner
            .lock()
            .transitions
            .iter()
            .filter(|(r, _)| *r == run)
            .map(|(_, t)| t.clone())
            .collect()
    }

    /// Every row of `run` across every table, one `table<TAB>json` line each, in table then
    /// insertion order. Rows are rendered the way the SQL stores persist them (serde JSON for
    /// records, `Debug` for the trail mirrors), so a scan of the output sees what a database
    /// dump would show (the canary test).
    #[must_use]
    pub fn dump_run(&self, run: CrawlRunId) -> String {
        fn json<T: serde::Serialize>(v: &T) -> String {
            serde_json::to_string(v).unwrap_or_else(|e| format!("<unserializable: {e}>"))
        }
        let g = self.inner.lock();
        let mut out = String::new();
        let mut line = |table: &str, body: String| {
            out.push_str(table);
            out.push('\t');
            out.push_str(&body);
            out.push('\n');
        };
        if let Some(r) = g.runs.get(&run) {
            line("crawl_runs", json(r));
        }
        for s in g.sessions.values().filter(|s| s.s.run == run) {
            line("crawl_sessions", json(&s.s));
        }
        for f in g.frontier.iter().filter(|f| f.e.run == run) {
            line("url_frontier", json(&f.e));
        }
        for p in g.pages.iter().filter(|p| p.run == run) {
            line("pages", json(p));
        }
        for id in &g.action_order {
            if let Some(a) = g.actions.get(id).filter(|a| a.rec.run == run) {
                line("actions", json(&a.rec));
            }
        }
        for s in g.states.iter().filter(|s| g.state_runs.get(&s.id) == Some(&run)) {
            line("states", json(s));
        }
        for c in g.clusters.iter().filter(|c| c.run == run) {
            line(
                "state_clusters",
                format!(
                    "{{\"id\":{},\"members\":{},\"version\":{},\"superseded\":{},\"signature\":{}}}",
                    json(&c.id),
                    c.members,
                    c.version,
                    c.superseded,
                    json(&c.signature)
                ),
            );
        }
        for e in g.edges.iter().filter(|e| e.run == run) {
            line("enablement_edges", json(e));
        }
        for ((r, _), row) in &g.ledger {
            if *r == run {
                line("action_contexts", json(row));
            }
        }
        for ev in g.events.get(&run).into_iter().flatten() {
            line("crawl_events", json(ev));
        }
        for (r, session, verdict, summary) in &g.safety {
            if *r == run {
                line(
                    "safety_decisions",
                    format!(
                        "{{\"session\":{},\"verdict\":{},\"summary\":{}}}",
                        json(session),
                        json(verdict),
                        json(summary)
                    ),
                );
            }
        }
        for (action, t) in &g.traffic {
            if g.actions.get(action).is_some_and(|row| row.rec.run == run) {
                line("traffic_events", json(t));
            }
        }
        for (r, t) in &g.transitions {
            if *r == run {
                line("transitions", format!("{t:?}"));
            }
        }
        for (r, e) in &g.network_epochs {
            if *r == run {
                line("network_epochs", format!("{e:?}"));
            }
        }
        for c in g.checkpoints.iter().filter(|c| c.run == run) {
            line("checkpoints", json(c));
        }
        for d in g.model_decisions.iter().filter(|d| d.run == run) {
            line("model_decisions", json(d));
        }
        for (r, a) in &g.identity_aliases {
            if *r == run {
                line("identity_aliases", json(a));
            }
        }
        out
    }

    /// Network epochs written by T2 for `run`, in write order (the trail).
    #[must_use]
    pub fn network_epochs(&self, run: CrawlRunId) -> Vec<MemoryNetworkEpoch> {
        self.inner
            .lock()
            .network_epochs
            .iter()
            .filter(|(r, _)| *r == run)
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Session lease TTL this store applies.
    #[must_use]
    pub const fn session_ttl(&self) -> Duration {
        self.session_ttl
    }

    /// Mirror of `Pg::eligible_actions`.
    #[must_use]
    pub fn eligible_actions(&self, run: CrawlRunId, session: Option<SessionId>) -> Vec<ActionRecord> {
        let g = self.inner.lock();
        g.action_order
            .iter()
            .filter_map(|id| g.actions.get(id))
            .filter(|a| {
                a.rec.run == run && session.is_none_or(|s| a.rec.session == s) && a.hold == Hold::None
            })
            .filter(|a| {
                a.rec.status == ActionStatus::Proposed
                    || (a.rec.status == ActionStatus::Reconciled
                        && a.rec.reconcile_resolution
                            == Some(crawlx_core::counters::ReconcileResolution::NotApplied))
            })
            .map(|a| a.rec.clone())
            .collect()
    }

    /// Test hook: force a session lease to expire at `at` (simulates a holder that stopped heartbeating).
    pub fn expire_session_lease(&self, session: SessionId, at: Timestamp) {
        if let Some(r) = self.inner.lock().sessions.get_mut(&session) {
            r.expires = Some(at);
        }
    }

    /// Approval decision for a held action: approving releases the hold (the action becomes
    /// eligible), denying marks it denied. Returns `false` if the action does not exist.
    pub fn resolve_hold(&self, action: ActionId, approved: bool) -> bool {
        match self.inner.lock().actions.get_mut(&action) {
            Some(a) => {
                a.hold = if approved { Hold::None } else { Hold::Denied };
                true
            }
            None => false,
        }
    }

    /// Erasure: delete every row of `run` (the in-memory mirror of `RetentionSweeper::purge_run`).
    /// Returns the number of rows removed.
    pub fn purge_run(&self, run: CrawlRunId) -> u64 {
        self.archives.lock().purge_run(run);
        let mut g = self.inner.lock();
        let mut n = 0u64;
        let doomed_actions: Vec<ActionId> = g
            .actions
            .iter()
            .filter(|(_, a)| a.rec.run == run)
            .map(|(id, _)| *id)
            .collect();
        n += doomed_actions.len() as u64;
        g.actions.retain(|_, a| a.rec.run != run);
        g.action_order.retain(|id| !doomed_actions.contains(id));
        let traffic_before = g.traffic.len();
        g.traffic.retain(|(a, _)| !doomed_actions.contains(a));
        n += (traffic_before - g.traffic.len()) as u64;
        let sessions: Vec<SessionId> = g
            .sessions
            .values()
            .filter(|r| r.s.run == run)
            .map(|r| r.s.id)
            .collect();
        n += sessions.len() as u64;
        g.sessions.retain(|_, r| r.s.run != run);
        for s in &sessions {
            g.session_seq.remove(s);
        }
        let before = g.frontier.len();
        g.frontier.retain(|f| f.e.run != run);
        n += (before - g.frontier.len()) as u64;
        g.dataset.purge_run(run);
        let before = g.adaptive_selectors.len();
        g.adaptive_selectors.retain(|_, record| record.run != run);
        n = n.saturating_add(
            u64::try_from(before.saturating_sub(g.adaptive_selectors.len())).unwrap_or(u64::MAX),
        );
        let before = g.pages.len();
        g.pages.retain(|p| p.run != run);
        n += (before - g.pages.len()) as u64;
        let before = g.page_captures.len();
        g.page_captures.retain(|(id, _), _| *id != run);
        n = n.saturating_add(u64::try_from(before.saturating_sub(g.page_captures.len())).unwrap_or(u64::MAX));
        let doomed_states: Vec<StateId> = g
            .state_runs
            .iter()
            .filter(|(_, r)| **r == run)
            .map(|(s, _)| *s)
            .collect();
        n += doomed_states.len() as u64;
        g.states.retain(|s| !doomed_states.contains(&s.id));
        g.state_runs.retain(|_, r| *r != run);
        let before = g.clusters.len();
        g.clusters.retain(|c| c.run != run);
        n += (before - g.clusters.len()) as u64;
        let before = g.edges.len();
        g.edges.retain(|e| e.run != run);
        n += (before - g.edges.len()) as u64;
        let before = g.ledger.len();
        g.ledger.retain(|(r, _), _| *r != run);
        n += (before - g.ledger.len()) as u64;
        n += g.events.remove(&run).map_or(0, |v| v.len() as u64);
        let before = g.safety.len();
        g.safety.retain(|(r, _, _, _)| *r != run);
        n += (before - g.safety.len()) as u64;
        let before = g.checkpoints.len();
        g.checkpoints.retain(|c| c.run != run);
        n += (before - g.checkpoints.len()) as u64;
        g.idempotency.retain(|_, (r, _)| *r != run);
        g.replay_specs.remove(&run);
        n += u64::from(g.runs.remove(&run).is_some());
        n
    }
}

fn push_event(g: &mut Inner, run: CrawlRunId, kind: &str, payload: serde_json::Value, at: Timestamp) -> u64 {
    let list = g.events.entry(run).or_default();
    let seq = list.len() as u64 + 1;
    list.push(RunEvent {
        seq,
        kind: kind.to_owned(),
        payload,
        at,
    });
    seq
}

fn ensure_ledger<'a>(
    g: &'a mut Inner,
    run: CrawlRunId,
    key: &ActionContextKey,
    now: Timestamp,
) -> &'a mut LedgerRow {
    g.ledger.entry((run, key.id())).or_insert_with(|| LedgerRow {
        key: key.clone(),
        trusted_exercised: 0,
        diagnostic_exercised: 0,
        failures: 0,
        first_seen: now,
        last_exercised: None,
    })
}

fn insert_state(g: &mut Inner, run: CrawlRunId, s: &NewState) -> Result<(), StoreError> {
    if g.states.iter().any(|x| x.id == s.id) {
        return Ok(());
    }
    if s.cluster_is_new {
        if !g.clusters.iter().any(|c| c.id == s.cluster) {
            g.clusters.push(ClusterRow {
                id: s.cluster,
                run,
                signature: s.signature.clone(),
                members: 0,
                version: 1,
                superseded: false,
            });
        }
    } else if !g.clusters.iter().any(|c| c.id == s.cluster && !c.superseded) {
        return Err(nf("state_cluster", s.cluster));
    }
    if let Some(c) = g.clusters.iter_mut().find(|c| c.id == s.cluster) {
        c.members += 1;
    }
    g.state_runs.insert(s.id, run);
    g.states.push(s.clone());
    Ok(())
}

/// `intended → unknown` for the actions of the sessions `pick` selects. `at` becomes the
/// action's `finished_at`: the instant the outcome was declared unknown (the
/// trail verifier requires a timestamp on every final-status row).
fn flip_unknown(g: &mut Inner, at: Timestamp, pick: impl Fn(&SessionId) -> bool) -> Vec<ActionId> {
    let mut flipped = Vec::new();
    for id in &g.action_order {
        if let Some(a) = g.actions.get_mut(id) {
            if a.rec.status == ActionStatus::Intended && pick(&a.rec.session) {
                a.rec.status = ActionStatus::Unknown;
                a.rec.finished_at = Some(at);
                flipped.push(*id);
            }
        }
    }
    flipped
}

#[async_trait]
impl RunRepo for MemoryStore {
    async fn create(&self, run: &CrawlRun, idempotency_key: Option<&str>) -> Result<(), StoreError> {
        let stored = self.durable_run(run).await?;
        let mut g = self.inner.lock();
        if g.runs.contains_key(&run.id) {
            return Err(StoreError::Conflict(format!("run {} exists", run.id)));
        }
        if let Some(k) = idempotency_key {
            if g.idempotency.contains_key(&(run.tenant, k.to_owned())) {
                return Err(StoreError::Conflict(format!(
                    "idempotency key {k:?} already used"
                )));
            }
            g.idempotency
                .insert((run.tenant, k.to_owned()), (run.id, run.config_digest));
        }
        g.runs.insert(run.id, stored);
        Ok(())
    }

    async fn create_replay(
        &self,
        run: &CrawlRun,
        sessions: &[CrawlSession],
        spec: &serde_json::Value,
    ) -> Result<(), StoreError> {
        let source: CrawlRunId = serde_json::from_value(
            spec.get("sourceRunId")
                .cloned()
                .ok_or_else(|| StoreError::Conflict("replay sourceRunId is required".to_owned()))?,
        )
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
        let stored = self.durable_run(run).await?;
        let mut g = self.inner.lock();
        if !g.runs.get(&source).is_some_and(|s| s.tenant == run.tenant) {
            return Err(nf("crawl_run", source));
        }
        if g.runs.contains_key(&run.id) {
            return Err(StoreError::Conflict(format!("run {} exists", run.id)));
        }
        // Validate every slot before publishing any row, matching a database transaction.
        for (i, session) in sessions.iter().enumerate() {
            if session.run != run.id {
                return Err(StoreError::Conflict(
                    "replay session belongs to another run".to_owned(),
                ));
            }
            let conflicts = |other: &CrawlSession| {
                other.id == session.id
                    || (other.run == session.run
                        && (other.schedule_slot == session.schedule_slot
                            || (other.role == session.role && other.run_index == session.run_index)))
            };
            if sessions[..i].iter().any(conflicts) || g.sessions.values().any(|row| conflicts(&row.s)) {
                return Err(StoreError::Conflict(format!(
                    "session {} conflicts with an existing slot",
                    session.id
                )));
            }
        }
        g.runs.insert(run.id, stored);
        g.replay_specs.insert(run.id, spec.clone());
        for session in sessions {
            g.sessions.insert(
                session.id,
                SessionRow {
                    s: session.clone(),
                    owner: None,
                    token: None,
                    expires: None,
                    render: false,
                },
            );
        }
        Ok(())
    }

    async fn replay_spec(&self, run: CrawlRunId) -> Result<Option<serde_json::Value>, StoreError> {
        let g = self.inner.lock();
        if !g.runs.contains_key(&run) {
            return Err(nf("crawl_run", run));
        }
        Ok(g.replay_specs.get(&run).cloned())
    }

    async fn get(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        self.inner
            .lock()
            .runs
            .get(&id)
            .cloned()
            .ok_or_else(|| nf("crawl_run", id))
    }

    async fn get_for_execution(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let mut run = RunRepo::get(self, id).await?;
        if run.config.fetch.has_literal_secrets() {
            let unavailable =
                || StoreError::RetentionDenied("literal request controls expired or unavailable".into());
            let buffer = self.dataset_delivery.lock().clone().ok_or_else(unavailable)?;
            let page = buffer
                .get(run.tenant, id, i64::MIN)
                .await?
                .ok_or_else(unavailable)?;
            let blob = page
                .blobs
                .get(&format!("_fetch_controls:{}", run.config_digest.to_hex()))
                .ok_or_else(unavailable)?;
            run.config.fetch = serde_json::from_slice(&blob.bytes)?;
        }
        Ok(run)
    }

    async fn set_status(
        &self,
        id: CrawlRunId,
        status: RunStatus,
        reason: Option<TerminalReason>,
    ) -> Result<(), StoreError> {
        if status.is_terminal() != reason.is_some() {
            return Err(StoreError::Conflict(
                "terminal_reason must be set exactly for terminal statuses".to_owned(),
            ));
        }
        let now = self.clock.now();
        let mut g = self.inner.lock();
        let run = g.runs.get_mut(&id).ok_or_else(|| nf("crawl_run", id))?;
        if run.status.is_terminal() {
            return Err(StoreError::IllegalTransition {
                from: run.status.as_str().to_owned(),
                to: status.as_str().to_owned(),
            });
        }
        run.status = status;
        run.terminal_reason = reason;
        if status == RunStatus::Running {
            run.started_at.get_or_insert(now);
        }
        if status.is_terminal() {
            run.finished_at = Some(now);
            for checkpoint in g.checkpoints.iter_mut().filter(|checkpoint| checkpoint.run == id) {
                checkpoint.expires_at = checkpoint.expires_at.min(now);
            }
        }
        Ok(())
    }

    async fn update_counters(&self, id: CrawlRunId, counters: PlaneCounters) -> Result<(), StoreError> {
        self.inner
            .lock()
            .runs
            .get_mut(&id)
            .ok_or_else(|| nf("crawl_run", id))?
            .counters = counters;
        Ok(())
    }

    async fn set_trace_id(&self, run: CrawlRunId, trace_id: TraceId) -> Result<(), StoreError> {
        self.inner
            .lock()
            .runs
            .get_mut(&run)
            .ok_or_else(|| nf("crawl_run", run))?
            .trace_id = Some(trace_id);
        Ok(())
    }

    async fn create_sessions(&self, sessions: &[CrawlSession]) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        for s in sessions {
            if !g.runs.contains_key(&s.run) {
                return Err(nf("crawl_run", s.run));
            }
            let dup = g.sessions.values().any(|r| {
                r.s.id == s.id
                    || (r.s.run == s.run
                        && (r.s.schedule_slot == s.schedule_slot
                            || (r.s.role == s.role && r.s.run_index == s.run_index)))
            });
            if dup {
                return Err(StoreError::Conflict(format!(
                    "session {} conflicts with an existing slot",
                    s.id
                )));
            }
            g.sessions.insert(
                s.id,
                SessionRow {
                    s: s.clone(),
                    owner: None,
                    token: None,
                    expires: None,
                    render: false,
                },
            );
        }
        Ok(())
    }

    async fn list_sessions(&self, run: CrawlRunId) -> Result<Vec<CrawlSession>, StoreError> {
        let mut v: Vec<CrawlSession> = self
            .inner
            .lock()
            .sessions
            .values()
            .filter(|r| r.s.run == run)
            .map(|r| r.s.clone())
            .collect();
        v.sort_by_key(|s| s.schedule_slot);
        Ok(v)
    }

    async fn set_session_status(&self, id: SessionId, status: SessionStatus) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let r = g.sessions.get_mut(&id).ok_or_else(|| nf("crawl_session", id))?;
        if r.s.status.is_terminal() {
            return Err(StoreError::IllegalTransition {
                from: r.s.status.as_str().to_owned(),
                to: status.as_str().to_owned(),
            });
        }
        r.s.status = status;
        if status.is_terminal() {
            r.owner = None;
            r.expires = None;
        }
        Ok(())
    }

    async fn set_session_browser(&self, id: SessionId, info: &BrowserBuildInfo) -> Result<(), StoreError> {
        self.inner
            .lock()
            .sessions
            .get_mut(&id)
            .ok_or_else(|| nf("crawl_session", id))?
            .s
            .browser = Some(info.clone());
        Ok(())
    }
}

impl MemoryStore {
    /// Finish a leased frontier row; with a `fence`, only the holder of that lease can.
    fn complete_row(
        &self,
        id: i64,
        fence: Option<i64>,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError> {
        if matches!(status, FrontierStatus::Pending | FrontierStatus::Leased) {
            return Err(StoreError::IllegalTransition {
                from: "leased".to_owned(),
                to: status.as_str().to_owned(),
            });
        }
        let mut g = self.inner.lock();
        let f = g
            .frontier
            .iter_mut()
            .find(|f| f.e.id == id)
            .ok_or_else(|| nf("frontier row", id))?;
        if fence.is_some()
            && (f.e.status != FrontierStatus::Leased
                || f.token != fence
                || f.expires.is_none_or(|expires| expires <= self.clock.now()))
        {
            return Err(StoreError::LeaseLost);
        }
        if f.e.status != FrontierStatus::Leased {
            return Err(StoreError::IllegalTransition {
                from: f.e.status.as_str().to_owned(),
                to: status.as_str().to_owned(),
            });
        }
        f.e.status = status;
        if reason.is_some() {
            f.e.denial_reason = reason;
        }
        f.owner = None;
        f.expires = None;
        Ok(())
    }
}

#[async_trait]
impl FrontierRepo for MemoryStore {
    async fn append_batch(
        &self,
        batch: crawlx_core::orchestration::RequestBatchV1,
    ) -> Result<crawlx_core::orchestration::RequestBatchReceiptV1, StoreError> {
        self.request_append(batch).await
    }
    async fn page(&self, run: CrawlRunId, after: i64, limit: u32) -> Result<Vec<FrontierEntry>, StoreError> {
        self.request_page(run, after, limit).await
    }
    async fn metadata_page(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<crawlx_core::orchestration::RequestMetadataV1>, StoreError> {
        self.request_metadata_page(run, after, limit).await
    }
    async fn retry_fenced(&self, id: i64, fence: i64, not_before: Timestamp) -> Result<bool, StoreError> {
        self.request_retry(id, fence, not_before).await
    }
    async fn reserve_effects_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        effects: u32,
    ) -> Result<(), StoreError> {
        self.request_reserve(run, id, fence, effects).await
    }
    async fn settle_effects_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        reserved: u32,
        actual: u32,
    ) -> Result<(), StoreError> {
        self.request_settle_effects(run, id, fence, reserved, actual)
            .await
    }
    async fn reserve_acquisition_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
    ) -> Result<crawlx_core::acquisition::AcquisitionAllowanceV1, StoreError> {
        self.acquisition_reserve(run, id, fence).await
    }
    async fn settle_acquisition_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        usage: &crawlx_core::acquisition::AcquisitionUsageV1,
    ) -> Result<(), StoreError> {
        self.acquisition_settle(run, id, fence, usage).await
    }
    async fn get_request(
        &self,
        run: CrawlRunId,
        id: i64,
    ) -> Result<crawlx_core::orchestration::QueuedRequestV1, StoreError> {
        self.request_get(run, id).await
    }
    async fn seal(&self, run: CrawlRunId, expected_epoch: u64) -> Result<(), StoreError> {
        self.request_seal(run, expected_epoch).await
    }
    async fn activity(
        &self,
        run: CrawlRunId,
    ) -> Result<crawlx_core::orchestration::FrontierActivityV1, StoreError> {
        self.request_activity(run).await
    }
    async fn loader_cursor(
        &self,
        run: CrawlRunId,
        source: &str,
    ) -> Result<Option<crawlx_core::orchestration::LoaderCursorV1>, StoreError> {
        self.request_cursor(run, source).await
    }
    async fn discover(
        &self,
        run: CrawlRunId,
        url: &CanonicalUrl,
        depth: u16,
        from: Option<i64>,
        denial: Option<(FrontierStatus, String)>,
    ) -> Result<(DiscoveryOutcome, Option<i64>), StoreError> {
        let (status, reason, outcome) = match denial {
            None => (FrontierStatus::Pending, None, DiscoveryOutcome::Admitted),
            Some((FrontierStatus::PolicyBlocked, why)) => (
                FrontierStatus::PolicyBlocked,
                Some(why),
                DiscoveryOutcome::PolicyBlocked,
            ),
            Some((FrontierStatus::RobotsBlocked, why)) => (
                FrontierStatus::RobotsBlocked,
                Some(why),
                DiscoveryOutcome::RobotsBlocked,
            ),
            Some((other, _)) => {
                return Err(StoreError::Conflict(format!(
                    "a discovery denial must be policy_blocked or robots_blocked, got {}",
                    other.as_str()
                )))
            }
        };
        let now = self.clock.now();
        let mut g = self.inner.lock();
        if request_memory::known(&g, run, url.key, 0) {
            return Ok((DiscoveryOutcome::Duplicate, None));
        }
        let envelope = crawlx_core::request::RequestEnvelopeV1::get(url.clone(), depth, from);
        let envelope_bytes = request_memory::reserve_legacy(&g, run, &envelope, status)?;
        g.next_frontier_id = g
            .next_frontier_id
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("frontier id overflow".into()))?;
        let id = g.next_frontier_id;
        g.frontier.push(FrontierRow {
            e: FrontierEntry {
                id,
                run,
                url: url.clone(),
                depth,
                status,
                denial_reason: reason,
                attempts: 0,
                discovered_from: from,
            },
            key: url.key,
            strategy_score: crawlx_core::priority::priority_depth(&url.url, u32::from(depth), true),
            owner: None,
            token: None,
            expires: None,
            next_attempt_at: now,
        });
        request_memory::record_legacy(&mut g, run, id, envelope, envelope_bytes, now);
        Ok((outcome, Some(id)))
    }

    async fn lease_batch_fenced(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        limit: u32,
    ) -> Result<Vec<(FrontierEntry, i64)>, StoreError> {
        let now = self.clock.now();
        let ttl = chrono_dur(self.url_ttl);
        let mut g = self.inner.lock();
        let admitted = g.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
        if !self.acquisition_worker_ready(run, worker, admitted.config.acquisition.as_ref(), now)? {
            return Ok(Vec::new());
        }
        if !self.worker_data_ready(run, worker, &admitted.config, now)? {
            return Ok(Vec::new());
        }
        let cfg = admitted.config.orchestration.clone().unwrap_or_default();
        let strategy = admitted.config.scope.strategy;
        let limit = usize::try_from(limit.min(cfg.queue.batch_size)).unwrap_or(0);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut picked = std::collections::BinaryHeap::with_capacity(limit);
        for (index, row) in g.frontier.iter().enumerate() {
            if row.e.run != run
                || row.e.status != FrontierStatus::Pending
                || row.next_attempt_at > now
                || row.e.attempts == u16::MAX
            {
                continue;
            }
            let key = (
                std::cmp::Reverse(request_memory::priority(&g, row.e.id)),
                crawlx_core::priority::strategy_order(strategy, row.e.depth, row.strategy_score, row.e.id),
                index,
            );
            if picked.len() < limit {
                picked.push(key);
            } else if picked.peek().is_some_and(|worst| key < *worst) {
                picked.pop();
                picked.push(key);
            }
        }
        let mut out = Vec::with_capacity(picked.len());
        for (_, _, i) in picked.into_sorted_vec() {
            g.fence += 1;
            let token = g.fence;
            let f = &mut g.frontier[i];
            f.e.status = FrontierStatus::Leased;
            f.e.attempts += 1;
            f.owner = Some(worker);
            f.token = Some(token);
            f.expires = Some(now + ttl);
            out.push((f.e.clone(), token));
        }
        Ok(out)
    }

    async fn complete(
        &self,
        id: i64,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError> {
        self.complete_row(id, None, status, reason)
    }

    async fn complete_fenced(
        &self,
        id: i64,
        fence: i64,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError> {
        self.complete_row(id, Some(fence), status, reason)
    }

    async fn give_back(&self, id: i64, fence: i64) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let f = g
            .frontier
            .iter_mut()
            .find(|f| f.e.id == id)
            .ok_or_else(|| nf("frontier row", id))?;
        if f.e.status != FrontierStatus::Leased
            || f.token != Some(fence)
            || f.expires.is_none_or(|expires| expires <= self.clock.now())
        {
            return Err(StoreError::LeaseLost);
        }
        f.e.status = FrontierStatus::Pending;
        f.e.attempts = f.e.attempts.saturating_sub(1);
        f.owner = None;
        f.expires = None;
        Ok(())
    }

    async fn defer_fenced(&self, id: i64, fence: i64, not_before: Timestamp) -> Result<(), StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        let row = g
            .frontier
            .iter_mut()
            .find(|row| row.e.id == id)
            .ok_or_else(|| nf("frontier row", id))?;
        if row.e.status != FrontierStatus::Leased
            || row.token != Some(fence)
            || row.expires.is_none_or(|expires| expires <= now)
        {
            return Err(StoreError::LeaseLost);
        }
        row.e.status = FrontierStatus::Pending;
        row.e.attempts = row.e.attempts.saturating_sub(1);
        row.next_attempt_at = row.next_attempt_at.max(not_before);
        row.owner = None;
        row.expires = None;
        Ok(())
    }

    async fn pending_count(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        Ok(self
            .inner
            .lock()
            .frontier
            .iter()
            .filter(|f| f.e.run == run && f.e.status == FrontierStatus::Pending)
            .count() as u64)
    }

    async fn open_count(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        Ok(self
            .inner
            .lock()
            .frontier
            .iter()
            .filter(|f| {
                f.e.run == run && matches!(f.e.status, FrontierStatus::Pending | FrontierStatus::Leased)
            })
            .count() as u64)
    }

    async fn state_counts(&self, run: CrawlRunId) -> Result<FrontierStateCounts, StoreError> {
        Ok(FrontierStateCounts::tally(
            self.inner
                .lock()
                .frontier
                .iter()
                .filter(|f| f.e.run == run)
                .map(|f| &f.e),
        ))
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<FrontierEntry>, StoreError> {
        Ok(self
            .inner
            .lock()
            .frontier
            .iter()
            .filter(|f| f.e.run == run)
            .map(|f| f.e.clone())
            .collect())
    }
}

#[async_trait]
impl PageRepo for MemoryStore {
    async fn committed_page_keyset(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<PageRecord>, StoreError> {
        if !(1..=64).contains(&limit) {
            return Err(StoreError::Conflict("page keyset limit must be 1..64".into()));
        }
        let state = self.inner.lock();
        let source = state.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != source.tenant) {
            return Err(StoreError::AccessDenied("page capture tenant mismatch".into()));
        }
        if source.config.retention.mode == RetentionMode::Zdr {
            return Err(StoreError::RetentionDenied(
                "durable archive cannot read zdr pages".into(),
            ));
        }
        if source.config.retention.days != 0
            && source.created_at + ChronoDuration::days(i64::from(source.config.retention.days))
                <= self.clock.now()
        {
            return Err(StoreError::RetentionDenied(
                "committed page source expired".into(),
            ));
        }
        Ok(state
            .page_captures
            .range((
                std::ops::Bound::Excluded((run, after)),
                std::ops::Bound::Unbounded,
            ))
            .take_while(|((id, _), _)| *id == run)
            .take(usize::try_from(limit).unwrap_or(64))
            .map(|(_, page)| page.clone())
            .collect())
    }
    async fn put(&self, page: &PageRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        match g
            .pages
            .iter_mut()
            .find(|p| p.run == page.run && p.url.key == page.url.key)
        {
            Some(existing) => *existing = page.clone(),
            None => g.pages.push(page.clone()),
        }
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<PageRecord>, StoreError> {
        let mut v: Vec<PageRecord> = self
            .inner
            .lock()
            .pages
            .iter()
            .filter(|p| p.run == run)
            .cloned()
            .collect();
        v.sort_by_key(|p| p.fetched_at);
        Ok(v)
    }

    async fn recent_for_url(
        &self,
        tenant: TenantId,
        url: &CanonicalUrl,
        limit: u32,
    ) -> Result<Vec<PageRecord>, StoreError> {
        let g = self.inner.lock();
        let mut v: Vec<PageRecord> = g
            .pages
            .iter()
            .rev()
            .filter(|p| p.url.key == url.key && g.runs.get(&p.run).is_some_and(|r| r.tenant == tenant))
            .cloned()
            .collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.fetched_at));
        v.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(v)
    }

    async fn known_pages(
        &self,
        tenant: TenantId,
        domain: &str,
        subdomains: bool,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<KnownPage>, StoreError> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let below = format!(".{domain}");
        let g = self.inner.lock();
        let mut v: Vec<&PageRecord> = g
            .pages
            .iter()
            .rev()
            .filter(|p| {
                let host_ok = p
                    .url
                    .url
                    .host_str()
                    .is_some_and(|h| h == domain || (subdomains && h.ends_with(below.as_str())));
                host_ok
                    && p.status < 400
                    && !p.is_not_cacheable()
                    && g.runs.get(&p.run).is_some_and(|r| {
                        r.tenant == tenant
                            && r.config.retention.mode != RetentionMode::Zdr
                            && (r.config.retention.days == 0
                                || r.created_at + ChronoDuration::days(i64::from(r.config.retention.days))
                                    > now)
                    })
            })
            .collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.fetched_at));
        v.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(v.into_iter()
            .map(|p| KnownPage {
                url: p.url.clone(),
                title: p.title.clone(),
                description: p
                    .metadata
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                links: p.links.clone(),
            })
            .collect())
    }
}

#[async_trait]
impl StateRepo for MemoryStore {
    async fn put_state(&self, state: &NewState) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let run = g
            .sessions
            .get(&state.session)
            .map(|r| r.s.run)
            .ok_or_else(|| nf("crawl_session", state.session))?;
        insert_state(&mut g, run, state)
    }

    async fn list_states(&self, run: CrawlRunId) -> Result<Vec<NewState>, StoreError> {
        let g = self.inner.lock();
        let mut v: Vec<NewState> = g
            .states
            .iter()
            .filter(|s| g.state_runs.get(&s.id) == Some(&run))
            .cloned()
            .collect();
        v.sort_by_key(|s| (s.observed_at, s.id));
        Ok(v)
    }

    async fn list_clusters(
        &self,
        run: CrawlRunId,
    ) -> Result<Vec<(StateClusterId, StateSignature, u32)>, StoreError> {
        Ok(self
            .inner
            .lock()
            .clusters
            .iter()
            .filter(|c| c.run == run && !c.superseded)
            .map(|c| (c.id, c.signature.clone(), c.members))
            .collect())
    }

    async fn apply_split(&self, split: &ClusterSplitRecord) -> Result<SplitApplied, StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        if !g.runs.contains_key(&split.run) {
            return Err(nf("crawl_run", split.run));
        }
        let src = g
            .clusters
            .iter()
            .position(|c| c.id == split.source && c.run == split.run)
            .ok_or_else(|| nf("state_cluster", split.source))?;
        if g.clusters[src].superseded {
            return Err(StoreError::Conflict(format!(
                "state cluster {} is already superseded",
                split.source
            )));
        }
        if g.clusters[src].version != split.source_version {
            return Err(StoreError::Conflict(format!(
                "state cluster {} is at version {}, split computed against {}",
                split.source, g.clusters[src].version, split.source_version
            )));
        }
        if split
            .successors
            .iter()
            .any(|s| g.clusters.iter().any(|c| c.id == s.cluster))
        {
            return Err(StoreError::Conflict(
                "split successor id already exists".to_owned(),
            ));
        }
        let active: BTreeMap<StateId, usize> = g
            .states
            .iter()
            .enumerate()
            .filter(|(_, s)| s.cluster == split.source && g.state_runs.get(&s.id) == Some(&split.run))
            .map(|(i, s)| (s.id, i))
            .collect();
        let assigned = split_assignment(split, &active)?;

        for s in &split.successors {
            g.clusters.push(ClusterRow {
                id: s.cluster,
                run: split.run,
                signature: s.signature.clone(),
                members: u32::try_from(s.members.len()).unwrap_or(u32::MAX),
                version: s.version,
                superseded: false,
            });
        }
        for (state, (to, similarity, prototype)) in &assigned {
            let i = active[state];
            let row = &mut g.states[i];
            row.cluster = *to;
            row.cluster_similarity = *similarity;
            row.cluster_is_new = *prototype;
        }
        g.clusters[src].superseded = true;
        g.clusters[src].members = 0;

        // Re-key the ledger: every context of the source goes to the successor its actions'
        // `before_state`s fall in; ties and contexts without action evidence go to the first.
        let mut evidence: BTreeMap<ActionContextId, BTreeMap<StateClusterId, u32>> = BTreeMap::new();
        for id in &g.action_order {
            let Some(a) = g.actions.get(id) else { continue };
            if a.rec.run != split.run || a.rec.key.state_cluster != split.source {
                continue;
            }
            if let Some((to, _, _)) = a.rec.before_state.and_then(|s| assigned.get(&s)) {
                *evidence
                    .entry(a.rec.key.id())
                    .or_default()
                    .entry(*to)
                    .or_insert(0) += 1;
            }
        }
        let mut old_ids: Vec<ActionContextId> = g
            .ledger
            .iter()
            .filter(|((r, _), row)| *r == split.run && row.key.state_cluster == split.source)
            .map(|((_, id), _)| *id)
            .collect();
        old_ids.sort_unstable();
        let mut rekeyed = 0_u32;
        for old in old_ids {
            let Some(mut row) = g.ledger.remove(&(split.run, old)) else {
                continue;
            };
            let target = pick_successor(split, evidence.get(&old));
            let old_key = row.key.clone();
            row.key.state_cluster = target;
            let new = row.key.id();
            g.ledger.insert((split.run, new), row);
            for a in g.actions.values_mut() {
                if a.rec.run == split.run && a.rec.key == old_key {
                    a.rec.key.state_cluster = target;
                }
            }
            for e in g.edges.iter_mut() {
                if e.run == split.run && e.source == old {
                    e.source = new;
                }
            }
            rekeyed += 1;
        }
        let applied = SplitApplied {
            memberships_moved: u32::try_from(assigned.len()).unwrap_or(u32::MAX),
            action_contexts_rekeyed: rekeyed,
        };
        push_event(
            &mut g,
            split.run,
            "state_cluster_split",
            split_event(split, applied),
            now,
        );
        Metrics::global().counter(names::STATES_SPLITS).inc();
        Ok(applied)
    }
}

/// Per moved state: `(successor, similarity, is the successor's prototype)`; fails unless the
/// successors partition `active` exactly and every prototype is one of its own members.
fn split_assignment(
    split: &ClusterSplitRecord,
    active: &BTreeMap<StateId, usize>,
) -> Result<BTreeMap<StateId, (StateClusterId, f32, bool)>, StoreError> {
    if split.successors.is_empty() {
        return Err(StoreError::Conflict("split without successors".to_owned()));
    }
    let mut assigned = BTreeMap::new();
    for s in &split.successors {
        if s.members.is_empty() {
            return Err(StoreError::Conflict(format!(
                "split successor {} has no members",
                s.cluster
            )));
        }
        if !s.members.iter().any(|m| m.state == s.prototype) {
            return Err(StoreError::Conflict(format!(
                "split successor {} prototype {} is not a member",
                s.cluster, s.prototype
            )));
        }
        for m in &s.members {
            if !active.contains_key(&m.state) {
                return Err(StoreError::Conflict(format!(
                    "state {} is not an active member of cluster {}",
                    m.state, split.source
                )));
            }
            if assigned
                .insert(m.state, (s.cluster, m.similarity, m.state == s.prototype))
                .is_some()
            {
                return Err(StoreError::Conflict(format!(
                    "state {} is assigned to two split successors",
                    m.state
                )));
            }
        }
    }
    if assigned.len() != active.len() {
        return Err(StoreError::Conflict(format!(
            "split moves {} of {} active members of cluster {}",
            assigned.len(),
            active.len(),
            split.source
        )));
    }
    Ok(assigned)
}

#[async_trait]
impl EdgeStore for MemoryStore {
    async fn upsert(&self, edge: &EdgeRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        if !g.ledger.contains_key(&(edge.run, edge.source)) {
            return Err(nf("action_context", edge.source));
        }
        match g.edges.iter_mut().find(|e| {
            e.run == edge.run
                && e.source == edge.source
                && e.context_cluster == edge.context_cluster
                && e.target == edge.target
        }) {
            Some(existing) => {
                let id = existing.id;
                *existing = edge.clone();
                existing.id = id;
            }
            None => g.edges.push(EdgeRecord {
                id: if edge.id.0.is_nil() {
                    EdgeId::new()
                } else {
                    edge.id
                },
                ..edge.clone()
            }),
        }
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<EdgeRecord>, StoreError> {
        Ok(self
            .inner
            .lock()
            .edges
            .iter()
            .filter(|e| e.run == run)
            .cloned()
            .collect())
    }
}

#[async_trait]
impl LedgerRepo for MemoryStore {
    async fn upsert(&self, run: CrawlRunId, row: &LedgerRow) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let slot = ensure_ledger(&mut g, run, &row.key, row.first_seen);
        let first = slot.first_seen.min(row.first_seen);
        *slot = row.clone();
        slot.first_seen = first;
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<LedgerRow>, StoreError> {
        let g = self.inner.lock();
        let mut rows: Vec<_> = g.ledger.iter().filter(|((r, _), _)| *r == run).collect();
        rows.sort_by(|((_, a_id), a), ((_, b_id), b)| a.first_seen.cmp(&b.first_seen).then(a_id.cmp(b_id)));
        Ok(rows.into_iter().map(|(_, row)| row.clone()).collect())
    }
}

#[async_trait]
impl SafetyAudit for MemoryStore {
    async fn record(
        &self,
        run: CrawlRunId,
        session: SessionId,
        v: &SafetyVerdict,
        summary: &str,
    ) -> Result<(), StoreError> {
        self.inner
            .lock()
            .safety
            .push((run, session, v.clone(), summary.to_owned()));
        Ok(())
    }
}

#[async_trait]
impl EventRepo for MemoryStore {
    async fn append(
        &self,
        run: CrawlRunId,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        if !g.runs.contains_key(&run) {
            return Err(nf("crawl_run", run));
        }
        Ok(push_event(&mut g, run, kind, payload, now))
    }

    async fn list_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        Ok(self
            .inner
            .lock()
            .events
            .get(&run)
            .map(|v| {
                v.iter()
                    .filter(|e| e.seq > after_seq)
                    .take(limit as usize)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[async_trait]
impl CheckpointRepo for MemoryStore {
    async fn put(&self, checkpoint: &CheckpointRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        if !g.sessions.contains_key(&checkpoint.session) {
            return Err(nf("crawl_session", checkpoint.session));
        }
        g.checkpoints.retain(|c| c.id != checkpoint.id);
        g.checkpoints.push(checkpoint.clone());
        // keep the newest three per session
        let mut mine: Vec<(u64, Timestamp, CheckpointId)> = g
            .checkpoints
            .iter()
            .filter(|c| c.session == checkpoint.session)
            .map(|c| (c.action_seq, c.created_at, c.id))
            .collect();
        mine.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
        let doomed: Vec<CheckpointId> = mine.iter().skip(3).map(|m| m.2).collect();
        g.checkpoints.retain(|c| !doomed.contains(&c.id));
        Ok(())
    }

    async fn latest(&self, session: SessionId) -> Result<Option<CheckpointRecord>, StoreError> {
        Ok(CheckpointRepo::list(self, session).await?.into_iter().next())
    }

    async fn list(&self, session: SessionId) -> Result<Vec<CheckpointRecord>, StoreError> {
        let now = self.clock.now();
        let g = self.inner.lock();
        let mut v: Vec<CheckpointRecord> = g
            .checkpoints
            .iter()
            .filter(|c| c.session == session && c.expires_at > now)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.action_seq
                .cmp(&a.action_seq)
                .then(b.created_at.cmp(&a.created_at))
        });
        Ok(v)
    }
}

#[async_trait]
impl ActionJournal for MemoryStore {
    async fn propose(
        &self,
        run: CrawlRunId,
        session: SessionId,
        p: &ActionProposal,
        v: &SafetyVerdict,
    ) -> Result<ActionId, StoreError> {
        let now = self.clock.now();
        let id = ActionId::new();
        let fidelity = p.action.fidelity();
        let mut g = self.inner.lock();
        let seq = {
            let n = g.session_seq.entry(session).or_insert(0);
            *n += 1;
            *n
        };
        if let Some(r) = g.sessions.get_mut(&session) {
            r.s.action_seq = seq;
        }
        ensure_ledger(&mut g, run, &p.key, now);
        let hold = match v.decision {
            SafetyDecision::Allow => Hold::None,
            SafetyDecision::Deny => Hold::Denied,
            SafetyDecision::ApprovalRequired => Hold::AwaitingApproval,
        };
        let rec = ActionRecord {
            id,
            run,
            session,
            seq,
            key: p.key.clone(),
            status: ActionStatus::Proposed,
            attempt: 0,
            strategy: p.strategy.to_owned(),
            strategy_version: p.strategy_version,
            epoch: p.epoch,
            lane: Some(fidelity.lane()),
            fidelity: Some(fidelity),
            safety_decision: v.decision_id,
            model_decision: p.model_decision,
            before_state: None,
            reconcile_resolution: None,
            proposed_at: now,
            intended_at: None,
            finished_at: None,
            trace_id: crawlx_telemetry::current_trace_id(),
        };
        g.next_dataset_action = g
            .next_dataset_action
            .checked_add(1)
            .ok_or_else(|| StoreError::RetentionDenied("action dataset namespace exhausted".into()))?;
        let dataset_page = crate::dataset::action_page(g.next_dataset_action)?;
        g.safety.push((run, session, v.clone(), p.summary.clone()));
        g.action_order.push(id);
        g.actions.insert(
            id,
            ActionRow {
                rec,
                hold,
                dataset_page,
            },
        );
        Ok(id)
    }

    async fn intend(
        &self,
        id: ActionId,
        session: SessionId,
        epoch: ObservationEpoch,
    ) -> Result<(), StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        let (status, resolution, attempt, hold, owner_session) = {
            let a = g.actions.get(&id).ok_or_else(|| nf("action", id))?;
            (
                a.rec.status,
                a.rec.reconcile_resolution,
                a.rec.attempt,
                a.hold,
                a.rec.session,
            )
        };
        if owner_session != session {
            return Err(StoreError::Conflict(format!(
                "action {id} belongs to another session"
            )));
        }
        if let Some(s) = g.sessions.get(&session) {
            if !matches!(s.s.status, SessionStatus::Running | SessionStatus::Recovering) {
                return Err(StoreError::LeaseLost);
            }
        }
        if hold != Hold::None {
            return Err(StoreError::Conflict(format!("action {id} is held")));
        }
        let next_attempt = match (status, resolution) {
            (ActionStatus::Proposed, _) => attempt,
            (ActionStatus::Reconciled, Some(crawlx_core::counters::ReconcileResolution::NotApplied)) => {
                attempt + 1
            }
            _ => {
                return Err(StoreError::IllegalTransition {
                    from: status.as_str().to_owned(),
                    to: "intended".to_owned(),
                })
            }
        };
        let before = g
            .states
            .iter()
            .filter(|s| s.session == session && s.epoch <= epoch)
            .max_by_key(|s| (s.epoch, s.observed_at))
            .map(|s| s.id);
        let a = g.actions.get_mut(&id).ok_or_else(|| nf("action", id))?;
        a.rec.status = ActionStatus::Intended;
        a.rec.attempt = next_attempt;
        a.rec.intended_at = Some(now);
        a.rec.finished_at = None;
        a.rec.epoch = epoch;
        a.rec.before_state = before.or(a.rec.before_state);
        Ok(())
    }

    async fn finish(&self, id: ActionId, outcome: OutcomeRecord) -> Result<(), StoreError> {
        self.finish_with_accepted(id, outcome, 0, Vec::new(), Vec::new(), Vec::new())
            .await
    }

    async fn dataset_page(&self, id: ActionId) -> Result<i64, StoreError> {
        let g = self.inner.lock();
        let action = g.actions.get(&id).ok_or_else(|| nf("action", id))?;
        if crate::tenant::current()
            .is_some_and(|tenant| g.runs.get(&action.rec.run).is_none_or(|run| run.tenant != tenant))
        {
            return Err(StoreError::AccessDenied("action dataset tenant mismatch".into()));
        }
        Ok(action.dataset_page)
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
        self.validate_action_dataset_results(id, &accepted, &state_deltas, &outbox)
            .await?;
        let mut g = self.inner.lock();
        let (status, run, key, proposed_lane, before) = {
            let a = g.actions.get(&id).ok_or_else(|| nf("action", id))?;
            (
                a.rec.status,
                a.rec.run,
                a.rec.key.clone(),
                a.rec.lane.unwrap_or(TrustLane::Diagnostic),
                a.rec.before_state,
            )
        };
        // The lane is derived once from the executor's receipt; the proposal's
        // fidelity is only a plan. An outcome without a receipt keeps the proposed lane.
        let receipt_fidelity = outcome.receipt.as_ref().map(|r| r.fidelity);
        let lane = receipt_fidelity.map_or(proposed_lane, crawlx_core::traffic::Fidelity::lane);
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
        // validate everything fallible before mutating, so T2 stays all-or-nothing
        let receipt_epoch = outcome.receipt.as_ref().map(|r| r.network_epoch);
        for t in &outcome.traffic {
            crate::repos::traffic_attribution(t, receipt_epoch)?;
        }
        let staged_dataset = if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            let session = g.actions.get(&id).ok_or_else(|| nf("action", id))?.rec.session;
            let live = g.sessions.get(&session).is_some_and(|row| {
                row.token == Some(session_fence) && row.expires.is_some_and(|end| end > self.clock.now())
            });
            if !live || session_fence <= 0 || outcome.status != ActionStatus::Succeeded {
                return Err(StoreError::LeaseLost);
            }
            let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
            Some(crate::dataset::prepare_memory_action(
                &g.dataset,
                owner,
                id,
                &accepted,
                &state_deltas,
                &outbox,
                self.clock.now(),
            )?)
        } else {
            None
        };
        if let Some(after) = &outcome.after_state {
            let new_cluster_ok = after.cluster_is_new || g.clusters.iter().any(|c| c.id == after.cluster);
            if !new_cluster_ok {
                return Err(nf("state_cluster", after.cluster));
            }
            insert_state(&mut g, run, after)?;
        }
        if let Some(staged) = staged_dataset {
            crate::dataset::apply_prepared(&mut g.dataset, staged);
        }
        let request_count = u64::try_from(outcome.traffic.len()).unwrap_or(u64::MAX);
        let settle_timeout = outcome.settle.as_ref().is_some_and(|s| s.settle_timeout);
        g.traffic.extend(outcome.traffic.into_iter().map(|t| (id, t)));
        let session = {
            let a = g.actions.get_mut(&id).ok_or_else(|| nf("action", id))?;
            a.rec.status = outcome.status;
            a.rec.finished_at = Some(outcome.finished_at);
            if let Some(f) = receipt_fidelity {
                a.rec.fidelity = Some(f);
            }
            a.rec.lane = Some(lane);
            a.rec.session
        };
        if let Some(receipt) = &outcome.receipt {
            if !g
                .network_epochs
                .iter()
                .any(|(_, e)| e.id == receipt.network_epoch)
            {
                g.network_epochs.push((
                    run,
                    MemoryNetworkEpoch {
                        id: receipt.network_epoch,
                        session,
                        action: id,
                        lane,
                        request_count,
                        settle_timeout,
                    },
                ));
            }
        }
        if let Some(before) = before {
            if !g.transitions.iter().any(|(_, t)| t.action == id) {
                g.transitions.push((
                    run,
                    MemoryTransition {
                        action: id,
                        session,
                        before,
                        after: outcome.after_state.as_ref().map(|s| s.id),
                        network_epoch: receipt_epoch,
                        lane,
                        settle_timeout,
                    },
                ));
            }
        }
        let row = ensure_ledger(&mut g, run, &key, outcome.finished_at);
        match outcome.status {
            ActionStatus::Succeeded if lane == TrustLane::TrustedUi => row.trusted_exercised += 1,
            ActionStatus::Succeeded => row.diagnostic_exercised += 1,
            ActionStatus::Failed => row.failures += 1,
            _ => {}
        }
        row.last_exercised = Some(outcome.finished_at);
        push_event(
            &mut g,
            run,
            "action.finished",
            serde_json::json!({ "action_id": id.0, "session_id": session.0, "status": outcome.status.as_str(), "lane": lane.as_str() }),
            outcome.finished_at,
        );
        Ok(())
    }

    async fn mark_unknown(&self, expired_before: Timestamp) -> Result<Vec<ActionId>, StoreError> {
        let mut g = self.inner.lock();
        let expired: Vec<SessionId> = g
            .sessions
            .values()
            .filter(|r| {
                matches!(r.s.status, SessionStatus::Running | SessionStatus::Recovering)
                    && r.expires.is_some_and(|e| e < expired_before)
            })
            .map(|r| r.s.id)
            .collect();
        let now = self.clock.now();
        Ok(flip_unknown(&mut g, now, |s| expired.contains(s)))
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
        self.validate_action_dataset_results(id, &accepted, &state_deltas, &outbox)
            .await?;
        let mut g = self.inner.lock();
        let staged = if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            let action = g.actions.get(&id).ok_or_else(|| nf("action", id))?;
            let live = g.sessions.get(&action.rec.session).is_some_and(|row| {
                row.token == Some(session_fence) && row.expires.is_some_and(|end| end > self.clock.now())
            });
            if !live
                || session_fence <= 0
                || r.resolution != crawlx_core::counters::ReconcileResolution::Applied
            {
                return Err(StoreError::LeaseLost);
            }
            let owner = g
                .runs
                .get(&action.rec.run)
                .ok_or_else(|| nf("crawl_run", action.rec.run))?;
            Some(crate::dataset::prepare_memory_action(
                &g.dataset,
                owner,
                id,
                &accepted,
                &state_deltas,
                &outbox,
                self.clock.now(),
            )?)
        } else {
            None
        };
        let (run, session) = {
            let a = g.actions.get_mut(&id).ok_or_else(|| nf("action", id))?;
            if !a.rec.status.can_transition_to(ActionStatus::Reconciled) {
                return Err(StoreError::IllegalTransition {
                    from: a.rec.status.as_str().to_owned(),
                    to: "reconciled".to_owned(),
                });
            }
            a.rec.status = ActionStatus::Reconciled;
            a.rec.reconcile_resolution = Some(r.resolution);
            (a.rec.run, a.rec.session)
        };
        if let Some(staged) = staged {
            crate::dataset::apply_prepared(&mut g.dataset, staged);
        }
        push_event(
            &mut g,
            run,
            "action.reconciled",
            serde_json::json!({ "action_id": id.0, "session_id": session.0, "resolution": r.resolution.as_str() }),
            r.reconciled_at,
        );
        Ok(())
    }

    async fn get(&self, id: ActionId) -> Result<ActionRecord, StoreError> {
        self.inner
            .lock()
            .actions
            .get(&id)
            .map(|a| a.rec.clone())
            .ok_or_else(|| nf("action", id))
    }

    async fn list(
        &self,
        run: CrawlRunId,
        status: Option<ActionStatus>,
    ) -> Result<Vec<ActionRecord>, StoreError> {
        let g = self.inner.lock();
        Ok(g.action_order
            .iter()
            .filter_map(|id| g.actions.get(id))
            .filter(|a| a.rec.run == run && status.is_none_or(|s| a.rec.status == s))
            .map(|a| a.rec.clone())
            .collect())
    }

    async fn outcome_counts(&self, run: CrawlRunId) -> Result<JournalOutcomes, StoreError> {
        let g = self.inner.lock();
        Ok(JournalOutcomes::tally(
            g.actions.values().map(|a| &a.rec).filter(|r| r.run == run),
        ))
    }
}

fn claim_memory(
    store: &MemoryStore,
    run: CrawlRunId,
    worker: WorkerId,
    parallel_roles_allowed: bool,
    requested: Option<SessionId>,
) -> Result<Option<SessionLease>, StoreError> {
    if !store.admission.lock().grants_leases() {
        return Ok(None);
    }
    let now = store.clock.now();
    let ttl = chrono_dur(store.session_ttl);
    let mut state = store.inner.lock();
    if !state
        .runs
        .get(&run)
        .is_some_and(|run| matches!(run.status, RunStatus::Queued | RunStatus::Running))
    {
        return Ok(None);
    }
    let admitted = state.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
    if !store.acquisition_worker_ready(run, worker, admitted.config.acquisition.as_ref(), now)? {
        return Ok(None);
    }
    if !store.worker_data_ready(run, worker, &admitted.config, now)? {
        return Ok(None);
    }
    let candidate = state
        .sessions
        .values()
        .filter(|row| !row.render && row.s.run == run && requested.is_none_or(|session| session == row.s.id))
        .filter(|row| match row.s.status {
            SessionStatus::Pending => true,
            SessionStatus::Recovering => row.expires.is_none_or(|expires| expires < now),
            _ => false,
        })
        .filter(|candidate| {
            parallel_roles_allowed
                || !state.sessions.values().any(|prior| {
                    !prior.render
                        && prior.s.run == run
                        && prior.s.schedule_slot < candidate.s.schedule_slot
                        && !prior.s.status.is_terminal()
                })
        })
        .min_by_key(|row| row.s.schedule_slot)
        .map(|row| row.s.id);
    let Some(session) = candidate else { return Ok(None) };
    state.fence = state
        .fence
        .checked_add(1)
        .ok_or_else(|| StoreError::Conflict("session fence exhausted".into()))?;
    let token = state.fence;
    let row = state
        .sessions
        .get_mut(&session)
        .ok_or_else(|| nf("crawl_session", session))?;
    if row.s.status == SessionStatus::Pending {
        row.s.status = SessionStatus::Running;
    }
    row.owner = Some(worker);
    row.token = Some(token);
    row.expires = Some(now + ttl);
    Ok(Some(SessionLease {
        session: row.s.clone(),
        worker,
        fencing_token: token,
        expires_at: now + ttl,
    }))
}

#[async_trait]
impl LeaseRepo for MemoryStore {
    async fn now(&self) -> Result<Timestamp, StoreError> {
        Ok(self.clock.now())
    }

    async fn admission(&self) -> Result<AdmissionMode, StoreError> {
        Ok(*self.admission.lock())
    }

    async fn active_runs(&self) -> Result<Vec<ActiveRun>, StoreError> {
        let g = self.inner.lock();
        let mut v: Vec<ActiveRun> = g
            .runs
            .values()
            .filter(|r| matches!(r.status, RunStatus::Queued | RunStatus::Running))
            .filter(|r| {
                g.sessions.values().any(|s| {
                    !s.render
                        && s.s.run == r.id
                        && matches!(s.s.status, SessionStatus::Pending | SessionStatus::Recovering)
                })
            })
            .map(|r| ActiveRun {
                run: r.id,
                parallel_roles_allowed: r.config.parallel_roles_allowed(),
            })
            .collect();
        v.sort_by_key(|a| a.run);
        Ok(v)
    }

    async fn claim_session(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError> {
        claim_memory(self, run, worker, parallel_roles_allowed, None)
    }

    async fn claim_session_exact(
        &self,
        run: CrawlRunId,
        session: SessionId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError> {
        claim_memory(self, run, worker, parallel_roles_allowed, Some(session))
    }

    async fn create_render_session(
        &self,
        session: &CrawlSession,
        worker: WorkerId,
    ) -> Result<SessionLease, StoreError> {
        crate::leases::validate_render_session(session)?;
        if !self.admission.lock().grants_leases() {
            return Err(StoreError::Unavailable("session admission is closed".into()));
        }
        let now = self.clock.now();
        let mut state = self.inner.lock();
        if !state
            .runs
            .get(&session.run)
            .is_some_and(|run| matches!(run.status, RunStatus::Queued | RunStatus::Running))
        {
            return Err(StoreError::Unavailable("render parent run is not live".into()));
        }
        let admitted = state
            .runs
            .get(&session.run)
            .ok_or_else(|| nf("crawl run", session.run))?;
        if !self.acquisition_worker_ready(session.run, worker, admitted.config.acquisition.as_ref(), now)? {
            return Err(StoreError::Unavailable(
                "render worker lacks fresh assigned backend capabilities".into(),
            ));
        }
        if !self.worker_data_ready(session.run, worker, &admitted.config, now)? {
            return Err(StoreError::Unavailable(
                "render worker lacks fresh approved data capabilities".into(),
            ));
        }
        if state.sessions.contains_key(&session.id)
            || state.sessions.values().any(|row| {
                row.s.run == session.run
                    && (row.s.schedule_slot == session.schedule_slot
                        || (row.s.role == session.role && row.s.run_index == session.run_index))
            })
        {
            return Err(StoreError::Conflict("render session slot already exists".into()));
        }
        state.fence = state
            .fence
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("session fence exhausted".into()))?;
        let token = state.fence;
        let mut session = session.clone();
        session.status = SessionStatus::Running;
        let expires_at = now + chrono_dur(self.session_ttl);
        state.sessions.insert(
            session.id,
            SessionRow {
                s: session.clone(),
                owner: Some(worker),
                token: Some(token),
                expires: Some(expires_at),
                render: true,
            },
        );
        Ok(SessionLease {
            session,
            worker,
            fencing_token: token,
            expires_at,
        })
    }

    async fn heartbeat(&self, lease: &SessionLease) -> Result<Timestamp, StoreError> {
        let now = self.clock.now();
        let ttl = chrono_dur(self.session_ttl);
        let mut g = self.inner.lock();
        let r = g
            .sessions
            .get_mut(&lease.session.id)
            .ok_or(StoreError::LeaseLost)?;
        if r.owner != Some(lease.worker)
            || r.token != Some(lease.fencing_token)
            || r.expires.is_none_or(|expiry| expiry <= now)
            || !matches!(r.s.status, SessionStatus::Running | SessionStatus::Recovering)
        {
            return Err(StoreError::LeaseLost);
        }
        r.expires = Some(now + ttl);
        Ok(now + ttl)
    }

    async fn release(&self, lease: &SessionLease, to: SessionStatus) -> Result<(), StoreError> {
        if !(to.is_terminal() || to == SessionStatus::Recovering) {
            return Err(StoreError::Conflict(format!(
                "cannot release a session into {}",
                to.as_str()
            )));
        }
        let mut g = self.inner.lock();
        let now = self.clock.now();
        let r = g
            .sessions
            .get_mut(&lease.session.id)
            .ok_or(StoreError::LeaseLost)?;
        if r.owner != Some(lease.worker)
            || r.token != Some(lease.fencing_token)
            || r.expires.is_none_or(|expiry| expiry <= now)
            || !matches!(r.s.status, SessionStatus::Running | SessionStatus::Recovering)
        {
            return Err(StoreError::LeaseLost);
        }
        r.s.status = to;
        r.owner = None;
        r.expires = None;
        if to == SessionStatus::Recovering {
            let id = lease.session.id;
            let now = self.clock.now();
            flip_unknown(&mut g, now, |s| *s == id);
        }
        Ok(())
    }

    async fn reap(&self, now: Timestamp) -> Result<ReapReport, StoreError> {
        let mut g = self.inner.lock();
        let mut recovering = Vec::new();
        for r in g.sessions.values_mut() {
            if r.s.status == SessionStatus::Running && r.expires.is_some_and(|e| e < now) {
                r.s.status = SessionStatus::Recovering;
                r.owner = None;
                r.expires = None;
                recovering.push(r.s.id);
            }
        }
        let actions = flip_unknown(&mut g, now, |s| recovering.contains(s));
        Ok(ReapReport {
            sessions_recovering: recovering,
            actions_unknown: actions,
        })
    }

    async fn reap_frontier(&self, now: Timestamp, max_attempts: u16) -> Result<FrontierReap, StoreError> {
        let mut g = self.inner.lock();
        let mut out = FrontierReap::default();
        for f in &mut g.frontier {
            if f.e.status == FrontierStatus::Leased && f.expires.is_some_and(|e| e < now) {
                f.owner = None;
                f.expires = None;
                if f.e.attempts >= max_attempts {
                    f.e.status = FrontierStatus::Failed;
                    f.e.denial_reason = Some("lease_expired".to_owned());
                    out.failed += 1;
                } else {
                    f.e.status = FrontierStatus::Pending;
                    out.requeued += 1;
                }
            }
        }
        Ok(out)
    }

    async fn heartbeat_frontier(
        &self,
        worker: WorkerId,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError> {
        let now = self.clock.now();
        let ttl = chrono_dur(self.url_ttl);
        let mut g = self.inner.lock();
        let mut renewed = Vec::new();
        for f in &mut g.frontier {
            if f.owner == Some(worker)
                && f.e.status == FrontierStatus::Leased
                && f.expires.is_some_and(|expires| expires > now)
                && leases
                    .iter()
                    .any(|&(id, fence)| id == f.e.id && f.token == Some(fence))
            {
                f.expires = Some(now + ttl);
                renewed.push(f.e.id);
            }
        }
        Ok(renewed)
    }

    fn url_batch_ttl(&self) -> Duration {
        self.url_ttl
    }
}

/// `ActionJournal`-only handle over a [`MemoryStore`].
#[derive(Clone)]
pub struct InMemoryJournal {
    store: Arc<MemoryStore>,
}

impl Default for InMemoryJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryJournal {
    /// Journal over a fresh store on the wall clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Arc::new(MemoryStore::new()),
        }
    }

    /// Journal sharing `store` (so lease reaping and journal agree).
    #[must_use]
    pub fn over(store: Arc<MemoryStore>) -> Self {
        Self { store }
    }

    /// The underlying store.
    #[must_use]
    pub fn store(&self) -> &Arc<MemoryStore> {
        &self.store
    }
}

#[async_trait]
impl ActionJournal for InMemoryJournal {
    async fn propose(
        &self,
        run: CrawlRunId,
        session: SessionId,
        p: &ActionProposal,
        v: &SafetyVerdict,
    ) -> Result<ActionId, StoreError> {
        self.store.propose(run, session, p, v).await
    }
    async fn intend(
        &self,
        id: ActionId,
        session: SessionId,
        epoch: ObservationEpoch,
    ) -> Result<(), StoreError> {
        self.store.intend(id, session, epoch).await
    }
    async fn finish(&self, id: ActionId, outcome: OutcomeRecord) -> Result<(), StoreError> {
        self.store.finish(id, outcome).await
    }
    async fn dataset_page(&self, id: ActionId) -> Result<i64, StoreError> {
        self.store.dataset_page(id).await
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
        self.store
            .finish_with_accepted(id, outcome, session_fence, accepted, state_deltas, outbox)
            .await
    }
    async fn mark_unknown(&self, expired_before: Timestamp) -> Result<Vec<ActionId>, StoreError> {
        self.store.mark_unknown(expired_before).await
    }
    async fn reconcile(&self, id: ActionId, r: Reconciliation) -> Result<(), StoreError> {
        self.store.reconcile(id, r).await
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
        self.store
            .reconcile_with_accepted(id, r, session_fence, accepted, state_deltas, outbox)
            .await
    }
    async fn get(&self, id: ActionId) -> Result<ActionRecord, StoreError> {
        ActionJournal::get(&*self.store, id).await
    }
    async fn list(
        &self,
        run: CrawlRunId,
        status: Option<ActionStatus>,
    ) -> Result<Vec<ActionRecord>, StoreError> {
        ActionJournal::list(&*self.store, run, status).await
    }
    async fn outcome_counts(&self, run: CrawlRunId) -> Result<JournalOutcomes, StoreError> {
        ActionJournal::outcome_counts(&*self.store, run).await
    }
}

#[async_trait]
impl ModelDecisionRepo for MemoryStore {
    async fn record(&self, decision: &ModelDecisionRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        if !g.runs.contains_key(&decision.run) {
            return Err(nf("crawl_run", decision.run));
        }
        if let Some(session) = decision.session {
            if !g.sessions.contains_key(&session) {
                return Err(nf("crawl_session", session));
            }
        }
        if !g.model_decisions.iter().any(|d| d.id == decision.id) {
            g.model_decisions.push(decision.clone());
        }
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<ModelDecisionRecord>, StoreError> {
        Ok(self
            .inner
            .lock()
            .model_decisions
            .iter()
            .filter(|d| d.run == run)
            .cloned()
            .collect())
    }
}

#[async_trait]
impl IdentityAliasRepo for MemoryStore {
    async fn record_alias(&self, run: CrawlRunId, alias: &IdentityAlias) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        if !g.runs.contains_key(&run) {
            return Err(nf("crawl_run", run));
        }
        let dup = g.identity_aliases.iter().any(|(r, a)| {
            *r == run
                && a.alias == alias.alias
                && a.canonical == alias.canonical
                && a.from_version == alias.from_version
                && a.to_version == alias.to_version
        });
        if !dup {
            g.identity_aliases.push((run, *alias));
        }
        Ok(())
    }

    async fn aliases_of(
        &self,
        run: CrawlRunId,
        canonical: ElementIdentityHash,
    ) -> Result<Vec<IdentityAlias>, StoreError> {
        let mut out: Vec<IdentityAlias> = self
            .inner
            .lock()
            .identity_aliases
            .iter()
            .filter(|(r, a)| *r == run && a.canonical == canonical)
            .map(|(_, a)| *a)
            .collect();
        out.sort_by_key(|a| (a.alias, a.from_version, a.to_version));
        Ok(out)
    }
}

#[path = "dataset_memory.rs"]
mod dataset_memory;
