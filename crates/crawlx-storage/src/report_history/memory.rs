//! Fenced, bounded report history for the in-process repository.
//!
//! Lock order is `MemoryStore::inner`, then `MemoryStore::report_history`.
//! Request commits prepare a bounded delta under both locks and apply it only
//! after every other fallible transaction check succeeds.

use super::*;
use crawlx_core::custody::{CustodyLease, CustodySource};
use crawlx_core::orchestration::RequestCommitV1;
use crawlx_core::report_history::{
    PipelineProgressV1, ReportDataV1, ReportEntryV1, ReportFactV1, ReportHistoryRepo, ReportPageV1,
    ReportQueryV1,
};
use std::ops::Bound::{Excluded, Unbounded};

const MAX_FACTS_PER_RUN: usize = 65_536;
const VOLATILE_SECONDS: i64 = 3_600;
type PipelineKey = (i64, u16);

#[derive(Default)]
struct RunHistory {
    identities: BTreeMap<Digest, u64>,
    pipelines: BTreeMap<PipelineKey, PipelineProgressV1>,
    expires_at: Timestamp,
    volatile: bool,
}

/// Bounded identities per run, with one repository-wide sequence space.
#[derive(Default)]
pub(crate) struct ReportState {
    entries: BTreeMap<u64, ReportFactV1>,
    runs: BTreeMap<CrawlRunId, RunHistory>,
    sequence: u64,
}

impl ReportState {
    /// Erase a run without recycling its global sequence numbers.
    pub(crate) fn purge_run(&mut self, run: CrawlRunId) -> u64 {
        let Some(history) = self.runs.remove(&run) else {
            return 0;
        };
        let count = u64::try_from(history.identities.len()).unwrap_or(u64::MAX);
        for sequence in history.identities.into_values() {
            self.entries.remove(&sequence);
        }
        count
    }

    fn expire(&mut self, now: Timestamp) {
        for history in self.runs.values_mut().filter(|history| history.expires_at <= now) {
            for sequence in history.identities.values() {
                self.entries.remove(sequence);
            }
            history.identities.clear();
            history.pipelines.clear();
            // Keep the original deadline tombstone: retries cannot restart a ZDR TTL.
        }
    }
}

fn retention_deadline(run: &CrawlRun, now: Timestamp) -> Result<Timestamp, StoreError> {
    let duration = if run.config.retention.mode == RetentionMode::Zdr {
        ChronoDuration::seconds(VOLATILE_SECONDS)
    } else {
        let days = run.config.retention.days;
        if !(1..=365).contains(&days) {
            return Err(StoreError::RetentionDenied("report retention is invalid".into()));
        }
        ChronoDuration::days(i64::from(days))
    };
    let origin = if run.config.retention.mode == RetentionMode::Zdr {
        now
    } else {
        run.created_at
    };
    let mut deadline = origin
        .checked_add_signed(duration)
        .ok_or_else(|| StoreError::RetentionDenied("report retention deadline overflow".into()))?;
    if run.config.retention.mode != RetentionMode::Zdr {
        if let Some(finished) = run.finished_at {
            let finish_deadline = finished
                .checked_add_signed(duration)
                .ok_or_else(|| StoreError::RetentionDenied("report retention deadline overflow".into()))?;
            deadline = deadline.min(finish_deadline);
        }
    }
    Ok(deadline)
}

/// Validate the current run and the real existing session or frontier fence.
///
/// # Errors
/// Returns lost-lease for cancellation, revocation, expiry or mismatched ownership.
/// Other custody source types do not grant report or graph producer authority.
pub(super) fn validate_lease(g: &Inner, lease: &CustodyLease, now: Timestamp) -> Result<(), StoreError> {
    lease.check_local_cancellation()?;
    let run = g.runs.get(&lease.run).ok_or(StoreError::LeaseLost)?;
    if run.tenant != lease.tenant
        || crate::tenant::current().is_some_and(|tenant| tenant != lease.tenant)
        || run.status.is_terminal()
        || run.terminal_reason.is_some()
        || g.pending_purges.contains_key(&lease.run)
        || lease.fence <= 0
        || (run.config.retention.mode != RetentionMode::Zdr && retention_deadline(run, now)? <= now)
    {
        return Err(StoreError::LeaseLost);
    }
    let valid = match lease.source {
        CustodySource::Session(id) => g.sessions.get(&id).is_some_and(|row| {
            row.s.run == lease.run
                && row.owner == Some(lease.worker)
                && row.token == Some(lease.fence)
                && row.expires.is_some_and(|expires| expires > now)
                && matches!(row.s.status, SessionStatus::Running | SessionStatus::Recovering)
        }),
        CustodySource::Url(id) => g.frontier.iter().any(|row| {
            row.e.id == id
                && row.e.run == lease.run
                && row.e.status == FrontierStatus::Leased
                && row.owner == Some(lease.worker)
                && row.token == Some(lease.fence)
                && row.expires.is_some_and(|expires| expires > now)
        }),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StoreError::LeaseLost)
    }
}

/// Validated delta; no report state changes occur until `apply_commit`.
#[must_use]
pub(super) struct PreparedReportFacts {
    run: CrawlRunId,
    expires_at: Timestamp,
    volatile: bool,
    entries: Vec<ReportEntryV1>,
    pipelines: BTreeMap<PipelineKey, PipelineProgressV1>,
    sequence: u64,
}

fn prepare_facts(
    state: &ReportState,
    run: &CrawlRun,
    facts: &[ReportFactV1],
    now: Timestamp,
) -> Result<PreparedReportFacts, StoreError> {
    prepare_facts_with_progress(state, run, facts, now, None)
}

fn prepare_facts_with_progress(
    state: &ReportState,
    run: &CrawlRun,
    facts: &[ReportFactV1],
    now: Timestamp,
    acknowledged: Option<(PipelineKey, PipelineProgressV1)>,
) -> Result<PreparedReportFacts, StoreError> {
    if facts.is_empty() {
        return Ok(PreparedReportFacts {
            run: run.id,
            expires_at: now,
            volatile: false,
            entries: Vec::new(),
            pipelines: BTreeMap::new(),
            sequence: state.sequence,
        });
    }
    let history = state.runs.get(&run.id);
    let volatile = run.config.retention.mode == RetentionMode::Zdr;
    let deadline = retention_deadline(run, now)?;
    let expires_at = history.map_or(deadline, |history| history.expires_at.min(deadline));
    if expires_at <= now || history.is_some_and(|history| history.volatile != volatile) {
        return Err(StoreError::RetentionDenied(
            "report history is unavailable".into(),
        ));
    }
    if facts.len() > MAX_FACTS_PER_RUN {
        return Err(StoreError::Conflict("report history capacity exceeded".into()));
    }
    let mut prepared = PreparedReportFacts {
        run: run.id,
        expires_at,
        volatile,
        entries: Vec::with_capacity(facts.len()),
        pipelines: acknowledged.into_iter().collect(),
        sequence: state.sequence,
    };
    let mut staged = BTreeMap::<Digest, usize>::new();
    for fact in facts {
        fact.validate()?;
        if fact.run != run.id || fact.tenant != run.tenant {
            return Err(StoreError::LeaseLost);
        }
        let existing = history
            .and_then(|history| history.identities.get(&fact.id))
            .and_then(|sequence| state.entries.get(sequence))
            .or_else(|| staged.get(&fact.id).map(|index| &prepared.entries[*index].fact));
        if let Some(existing) = existing {
            if existing != fact {
                return Err(StoreError::Conflict("report fact identity changed".into()));
            }
            continue;
        }
        let count = history.map_or(0, |history| history.identities.len());
        if count.saturating_add(prepared.entries.len()) >= MAX_FACTS_PER_RUN {
            return Err(StoreError::Conflict("report history capacity exceeded".into()));
        }
        if let Some(request) = fact.request_id {
            let key = (request, fact.attempt);
            let progress = prepared.pipelines.entry(key).or_insert_with(|| {
                history
                    .and_then(|history| history.pipelines.get(&key))
                    .cloned()
                    .unwrap_or_default()
            });
            progress.apply(&fact.data)?;
        } else if matches!(fact.data, ReportDataV1::Pipeline { .. }) {
            return Err(StoreError::Conflict(
                "pipeline fact requires a request identifier".into(),
            ));
        }
        prepared.sequence = prepared
            .sequence
            .checked_add(1)
            .filter(|sequence| i64::try_from(*sequence).is_ok())
            .ok_or_else(|| StoreError::Conflict("report sequence exhausted".into()))?;
        staged.insert(fact.id, prepared.entries.len());
        prepared
            .entries
            .push(ReportEntryV1::new(prepared.sequence, fact.clone()));
    }
    Ok(prepared)
}

/// Prepare request facts without cloning or mutating repository state.
///
/// The caller must hold the inner and report locks, validate live request and
/// optional observation leases, then apply this delta only after all other checks.
/// # Errors
/// Returns validation, capacity, changed-identity or pipeline progression errors.
pub(super) fn prepare_commit(
    state: &ReportState,
    run: &CrawlRun,
    commit: &RequestCommitV1,
    now: Timestamp,
    attempt: u16,
) -> Result<PreparedReportFacts, StoreError> {
    // A request row ends under its own fence even when the run was cancelled meanwhile (an
    // abandoned in-flight row); the run's state does not make its facts foreign.
    if commit.run != run.id || crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
        return Err(StoreError::LeaseLost);
    }
    for fact in &commit.report_facts {
        let url_source = fact.source == CustodySource::Url(commit.request_id) && fact.fence == commit.fence;
        let observation_source = commit
            .observation
            .as_ref()
            .is_some_and(|(lease, _)| fact.validate_lease(lease).is_ok());
        if fact.request_id != Some(commit.request_id)
            || fact.attempt != attempt
            || (!url_source && !observation_source)
        {
            return Err(StoreError::LeaseLost);
        }
    }
    let facts = crate::report_history::commit_checkpoints(commit, run.tenant, now, attempt)?;
    prepare_facts(state, run, &facts, now)
}

/// Prepare truthful completion after the real fenced outbox acknowledgement.
///
/// The caller holds the inner and report locks, checks a real nonempty set of
/// source-request outboxes, and passes whether every outbox is delivered after
/// the proposed acknowledgement. The original fact source is provenance, not
/// renewed acquisition authority. Missing parse evidence remains unknown.
///
/// # Errors
/// Returns malformed fact, bounded capacity or retention errors. Missing or
/// failed pipeline prerequisites leave the report unchanged, not the ACK failed.
pub(super) fn prepare_delivery_ack(
    state: &ReportState,
    run: &CrawlRun,
    request_id: i64,
    all_delivered: bool,
    now: Timestamp,
) -> Result<PreparedReportFacts, StoreError> {
    use crawlx_core::report_history::{PipelineStageV1, PipelineStateV1};
    let empty = || prepare_facts(state, run, &[], now);
    if !all_delivered || request_id <= 0 {
        return empty();
    }
    let Some(history) = state.runs.get(&run.id) else {
        return empty();
    };
    if history.expires_at <= now || retention_deadline(run, now)? <= now {
        return empty();
    }
    let original = history
        .identities
        .values()
        .filter_map(|sequence| state.entries.get(sequence).map(|fact| (*sequence, fact)))
        .filter(|(_, fact)| {
            fact.request_id == Some(request_id) && matches!(fact.data, ReportDataV1::Pipeline { .. })
        })
        .max_by_key(|(sequence, _)| *sequence)
        .map(|(_, fact)| fact);
    let Some(original) = original else { return empty() };
    let Some(progress) = history.pipelines.get(&(request_id, original.attempt)) else {
        return empty();
    };
    if progress.delivered() || progress.state(PipelineStageV1::Parse) != PipelineStateV1::Succeeded {
        return empty();
    }
    let mut progression = progress.clone();
    if progression.acknowledge_delivery().is_err() {
        return empty();
    }
    let mut facts = Vec::with_capacity(2);
    for stage in [PipelineStageV1::Index, PipelineStageV1::Completion] {
        let data = ReportDataV1::Pipeline {
            stage,
            state: PipelineStateV1::Succeeded,
        };
        let mut fact = original.clone();
        fact.id = Digest::of(
            "crawlx/report-delivery-ack/v1",
            &serde_json::to_vec(&(
                run.tenant,
                run.id,
                request_id,
                original.fence,
                original.attempt,
                stage,
            ))?,
        );
        fact.at = now;
        fact.data = data;
        facts.push(fact);
    }
    prepare_facts_with_progress(
        state,
        run,
        &facts,
        now,
        Some(((request_id, original.attempt), progression)),
    )
}

/// Apply a prepared delta under the same uninterrupted locks; cannot fail.
pub(super) fn apply_commit(state: &mut ReportState, prepared: PreparedReportFacts) {
    if prepared.entries.is_empty() {
        return;
    }
    let history = state.runs.entry(prepared.run).or_default();
    history.expires_at = prepared.expires_at;
    history.volatile = prepared.volatile;
    history.pipelines.extend(prepared.pipelines);
    for entry in prepared.entries {
        history.identities.insert(entry.fact.id, entry.sequence);
        state.entries.insert(entry.sequence, entry.fact);
    }
    state.sequence = prepared.sequence;
}

#[async_trait]
impl ReportHistoryRepo for MemoryStore {
    async fn append_fact(&self, lease: &CustodyLease, fact: &ReportFactV1) -> Result<u64, StoreError> {
        fact.validate()?;
        fact.validate_lease(lease)?;
        let binding = {
            let g = self.inner.lock();
            validate_lease(&g, lease, self.clock.now())?;
            g.runs
                .get(&lease.run)
                .ok_or(StoreError::LeaseLost)?
                .config
                .safety
                .authorization_record_ref
        };
        self.check_head_authority(lease.run).await?;
        let g = self.inner.lock();
        let now = self.clock.now();
        validate_lease(&g, lease, now)?;
        let run = g.runs.get(&lease.run).ok_or(StoreError::LeaseLost)?;
        if run.config.safety.authorization_record_ref != binding
            || matches!(lease.source, CustodySource::Url(id) if fact.request_id.is_some_and(|request| request != id))
        {
            return Err(StoreError::LeaseLost);
        }
        if let Some(request) = fact.request_id {
            if !g
                .frontier
                .iter()
                .any(|row| row.e.id == request && row.e.run == lease.run)
            {
                return Err(StoreError::LeaseLost);
            }
        }
        if let CustodySource::Url(id) = lease.source {
            let request = g
                .frontier
                .iter()
                .find(|row| row.e.id == id && row.e.run == lease.run)
                .ok_or(StoreError::LeaseLost)?;
            if fact.attempt != request.e.attempts.max(1) {
                return Err(StoreError::LeaseLost);
            }
        }
        let mut state = self.report_history.lock();
        state.expire(now);
        let prepared = prepare_facts(&state, run, std::slice::from_ref(fact), now)?;
        let sequence = prepared
            .entries
            .first()
            .map(|entry| entry.sequence)
            .or_else(|| state.runs.get(&run.id)?.identities.get(&fact.id).copied())
            .ok_or_else(|| StoreError::Conflict("report fact has no sequence".into()))?;
        apply_commit(&mut state, prepared);
        Ok(sequence)
    }

    async fn query_facts(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        query: &ReportQueryV1,
    ) -> Result<ReportPageV1, StoreError> {
        query.validate()?;
        if crate::tenant::current().is_some_and(|current| current != tenant) {
            return Err(StoreError::AccessDenied("report tenant mismatch".into()));
        }
        let bindings = {
            let g = self.inner.lock();
            if let Some(id) = run {
                let owner = g.runs.get(&id).ok_or_else(|| nf("crawl run", id))?;
                if owner.tenant != tenant {
                    return Err(StoreError::AccessDenied("report tenant mismatch".into()));
                }
                if owner.config.retention.mode == RetentionMode::Zdr {
                    return Err(StoreError::RetentionDenied(
                        "ZDR report history is volatile".into(),
                    ));
                }
            }
            let now = self.clock.now();
            let state = self.report_history.lock();
            let mut bindings = BTreeMap::new();
            for fact in state
                .entries
                .range((Excluded(query.after), Unbounded))
                .map(|(_, fact)| fact)
            {
                if fact.tenant != tenant || run.is_some_and(|id| fact.run != id) || !query.matches(fact) {
                    continue;
                }
                let Some(owner) = g.runs.get(&fact.run) else {
                    continue;
                };
                let Some(history) = state.runs.get(&fact.run) else {
                    continue;
                };
                if owner.tenant == tenant
                    && owner.config.retention.mode != RetentionMode::Zdr
                    && !history.volatile
                    && history.expires_at > now
                    && retention_deadline(owner, now)? > now
                    && owner.terminal_reason != Some(TerminalReason::AuthorizationRevoked)
                    && !g.pending_purges.contains_key(&owner.id)
                {
                    bindings.insert(owner.id, owner.config.safety.authorization_record_ref);
                }
            }
            bindings
        };
        for id in bindings.keys() {
            self.check_head_authority(*id).await?;
        }
        let g = self.inner.lock();
        let now = self.clock.now();
        let mut state = self.report_history.lock();
        state.expire(now);
        let limit = usize::try_from(query.limit)
            .map_err(|_| StoreError::Serialization("report limit overflow".into()))?;
        let mut entries = Vec::with_capacity(limit);
        let mut more = false;
        for (sequence, fact) in state.entries.range((Excluded(query.after), Unbounded)) {
            if fact.tenant != tenant || run.is_some_and(|id| fact.run != id) || !query.matches(fact) {
                continue;
            }
            let Some(owner) = g.runs.get(&fact.run) else {
                continue;
            };
            let Some(history) = state.runs.get(&fact.run) else {
                continue;
            };
            if !bindings
                .get(&fact.run)
                .is_some_and(|binding| *binding == owner.config.safety.authorization_record_ref)
                || owner.tenant != tenant
                || history.volatile
                || history.expires_at <= now
                || owner.config.retention.mode == RetentionMode::Zdr
                || retention_deadline(owner, now)? <= now
                || owner.terminal_reason == Some(TerminalReason::AuthorizationRevoked)
                || g.pending_purges.contains_key(&fact.run)
            {
                continue;
            }
            if entries.len() == limit {
                more = true;
                break;
            }
            entries.push(ReportEntryV1::new(*sequence, fact.clone()));
        }
        let next = if more {
            entries.last().map(|entry| entry.sequence)
        } else {
            None
        };
        Ok(ReportPageV1::new(entries, next))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::testkit::{canonical_url, crawl_run, create_crawl, sessions};
    use crawlx_core::report_history::{PipelineStageV1, PipelineStateV1, ReportKindV1};
    use crawlx_core::time::ManualClock;
    use tokio_util::sync::CancellationToken;

    async fn fixture(mode: RetentionMode) -> (MemoryStore, Arc<ManualClock>, CrawlRun, CustodyLease) {
        let now = Timestamp::from_timestamp(1_800_000_000, 0).unwrap();
        let clock = Arc::new(ManualClock::new(now));
        let store = MemoryStore::with_clock(clock.clone());
        let mut config = create_crawl("https://example.test/", &[], 1);
        config.retention.mode = mode;
        config.retention.days = if mode == RetentionMode::Zdr { 0 } else { 1 };
        let mut run = crawl_run(TenantId::new(), config);
        run.created_at = now;
        store.create(&run, None).await.unwrap();
        for ordinal in 1..=7 {
            let (_, id) = store
                .discover(
                    run.id,
                    &canonical_url(&format!("https://example.test/{ordinal}")),
                    0,
                    None,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(id, Some(ordinal));
        }
        store.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
        let worker = WorkerId::new();
        let session = store.claim_session(run.id, worker, false).await.unwrap().unwrap();
        let lease = CustodyLease::new(
            run.tenant,
            run.id,
            session.session.id,
            worker,
            session.fencing_token,
        );
        (store, clock, run, lease)
    }

    fn fact(lease: &CustodyLease, now: Timestamp, ordinal: u64) -> ReportFactV1 {
        ReportFactV1::new(
            lease,
            Digest::of("crawlx/report-memory-test", &ordinal.to_le_bytes()),
            now,
            ReportDataV1::Wire {
                received_bytes: Some(ordinal),
                sent_bytes: None,
                duration_us: Some(ordinal),
            },
        )
    }

    fn pipeline(
        lease: &CustodyLease,
        now: Timestamp,
        ordinal: u64,
        stage: PipelineStageV1,
        state: PipelineStateV1,
    ) -> ReportFactV1 {
        let mut fact = fact(lease, now, ordinal);
        fact.request_id = Some(7);
        fact.data = ReportDataV1::Pipeline { stage, state };
        fact
    }

    #[tokio::test]
    async fn same_identity_is_idempotent_but_changed_content_conflicts() {
        let (store, clock, run, lease) = fixture(RetentionMode::Standard).await;
        let original = fact(&lease, clock.now(), 1);
        let sequence = store.append_fact(&lease, &original).await.unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(store.append_fact(&lease, &original).await.unwrap(), sequence);
        let mut changed = original.clone();
        changed.at += ChronoDuration::microseconds(1);
        assert!(matches!(
            store.append_fact(&lease, &changed).await,
            Err(StoreError::Conflict(_))
        ));
        let page = store
            .query_facts(run.tenant, Some(run.id), &ReportQueryV1::default())
            .await
            .unwrap();
        assert_eq!(page.entries, vec![ReportEntryV1::new(1, original)]);
        assert_eq!(page.next, None);
    }

    #[tokio::test]
    async fn filters_precede_keyset_limit_and_use_matching_lookahead() {
        let (store, clock, run, lease) = fixture(RetentionMode::Standard).await;
        for ordinal in 1..=6 {
            store
                .append_fact(&lease, &fact(&lease, clock.now(), ordinal))
                .await
                .unwrap();
        }
        let mut query = ReportQueryV1::default();
        query.limit = 2;
        query.kind = Some(ReportKindV1::Wire);
        query.min_wire_bytes = Some(3);
        query.max_wire_bytes = Some(5);
        let first = store.query_facts(run.tenant, Some(run.id), &query).await.unwrap();
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            [3, 4]
        );
        assert_eq!(first.next, Some(4));
        query.after = first.next.unwrap();
        let last = store.query_facts(run.tenant, Some(run.id), &query).await.unwrap();
        assert_eq!(
            last.entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            [5]
        );
        assert_eq!(last.next, None);
        query.limit = 0;
        assert!(store.query_facts(run.tenant, Some(run.id), &query).await.is_err());
        query.limit = 65;
        assert!(store.query_facts(run.tenant, Some(run.id), &query).await.is_err());
    }

    #[tokio::test]
    async fn absent_facts_remain_empty_and_foreign_tenants_cannot_read() {
        let (store, clock, run, lease) = fixture(RetentionMode::Standard).await;
        let query = ReportQueryV1::default();
        assert!(store
            .query_facts(run.tenant, Some(run.id), &query)
            .await
            .unwrap()
            .entries
            .is_empty());
        store
            .append_fact(&lease, &fact(&lease, clock.now(), 1))
            .await
            .unwrap();
        let foreign = TenantId::new();
        assert!(matches!(
            store.query_facts(foreign, Some(run.id), &query).await,
            Err(StoreError::AccessDenied(_))
        ));
        assert!(store
            .query_facts(foreign, None, &query)
            .await
            .unwrap()
            .entries
            .is_empty());
        assert_eq!(
            store
                .query_facts(run.tenant, None, &query)
                .await
                .unwrap()
                .entries
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn forged_cancelled_terminal_and_expired_session_writes_leave_no_facts() {
        let (store, clock, run, lease) = fixture(RetentionMode::Standard).await;
        let original = fact(&lease, clock.now(), 1);
        let mut forged = lease.clone();
        forged.worker = WorkerId::new();
        assert!(matches!(
            store.append_fact(&forged, &original).await,
            Err(StoreError::LeaseLost)
        ));
        forged = lease.clone();
        forged.fence += 1;
        let forged_fact = fact(&forged, clock.now(), 2);
        assert!(matches!(
            store.append_fact(&forged, &forged_fact).await,
            Err(StoreError::LeaseLost)
        ));
        let cancel = CancellationToken::new();
        let cancelled = lease.clone().with_cancellation(cancel.clone());
        cancel.cancel();
        assert!(matches!(
            store.append_fact(&cancelled, &original).await,
            Err(StoreError::LeaseLost)
        ));
        store.inner.lock().runs.get_mut(&run.id).unwrap().status = RunStatus::Cancelled;
        assert!(matches!(
            store.append_fact(&lease, &original).await,
            Err(StoreError::LeaseLost)
        ));
        store.inner.lock().runs.get_mut(&run.id).unwrap().status = RunStatus::Running;
        let CustodySource::Session(session) = lease.source else {
            panic!("session fixture")
        };
        store.inner.lock().sessions.get_mut(&session).unwrap().expires = Some(clock.now());
        assert!(matches!(
            store.append_fact(&lease, &original).await,
            Err(StoreError::LeaseLost)
        ));
        assert!(store.report_history.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn zdr_is_never_disclosed_and_first_insert_ttl_cannot_refresh() {
        let (store, clock, run, lease) = fixture(RetentionMode::Zdr).await;
        let original = fact(&lease, clock.now(), 1);
        store.append_fact(&lease, &original).await.unwrap();
        let deadline = store.report_history.lock().runs[&run.id].expires_at;
        let CustodySource::Session(session) = lease.source else {
            panic!("session fixture")
        };
        store.inner.lock().sessions.get_mut(&session).unwrap().expires =
            Some(clock.now() + ChronoDuration::hours(2));
        clock.advance_ms(1_800_000);
        assert_eq!(store.append_fact(&lease, &original).await.unwrap(), 1);
        store
            .append_fact(&lease, &fact(&lease, clock.now(), 2))
            .await
            .unwrap();
        assert_eq!(store.report_history.lock().runs[&run.id].expires_at, deadline);
        assert!(matches!(
            store
                .query_facts(run.tenant, Some(run.id), &ReportQueryV1::default())
                .await,
            Err(StoreError::RetentionDenied(_))
        ));
        assert!(store
            .query_facts(run.tenant, None, &ReportQueryV1::default())
            .await
            .unwrap()
            .entries
            .is_empty());
        clock.advance_ms(1_800_000);
        assert!(matches!(
            store.append_fact(&lease, &fact(&lease, clock.now(), 3)).await,
            Err(StoreError::RetentionDenied(_))
        ));
        assert!(store.report_history.lock().entries.is_empty());
        assert_eq!(store.report_history.lock().runs[&run.id].expires_at, deadline);
    }

    #[tokio::test]
    async fn retained_expiry_uses_creation_not_late_append_or_finish() {
        let (store, clock, run, lease) = fixture(RetentionMode::Standard).await;
        store
            .append_fact(&lease, &fact(&lease, clock.now(), 1))
            .await
            .unwrap();
        let deadline = run.created_at + ChronoDuration::days(1);
        assert_eq!(store.report_history.lock().runs[&run.id].expires_at, deadline);
        clock.advance_ms(86_400_000);
        assert!(store
            .query_facts(run.tenant, Some(run.id), &ReportQueryV1::default())
            .await
            .unwrap()
            .entries
            .is_empty());
        assert!(store.report_history.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn commit_preparation_is_atomic_and_requires_committed_pipeline_dependencies() {
        let (_, clock, run, session_lease) = fixture(RetentionMode::Standard).await;
        let lease = CustodyLease::for_url(run.tenant, run.id, 7, session_lease.worker, 12);
        let mut commit = RequestCommitV1::terminal(run.id, 7, 12, 1, FrontierStatus::Succeeded, None);
        commit.report_facts.push(pipeline(
            &lease,
            clock.now(),
            1,
            PipelineStageV1::Fetch,
            PipelineStateV1::Succeeded,
        ));
        commit.report_facts.push(pipeline(
            &lease,
            clock.now(),
            2,
            PipelineStageV1::Index,
            PipelineStateV1::Succeeded,
        ));
        let mut state = ReportState::default();
        assert!(matches!(
            prepare_commit(&state, &run, &commit, clock.now(), 1),
            Err(StoreError::Conflict(_))
        ));
        assert!(state.entries.is_empty());
        assert_eq!(state.sequence, 0);
        commit.report_facts.insert(
            1,
            pipeline(
                &lease,
                clock.now(),
                3,
                PipelineStageV1::Parse,
                PipelineStateV1::Succeeded,
            ),
        );
        let staged = prepare_commit(&state, &run, &commit, clock.now(), 1).unwrap();
        assert!(state.entries.is_empty());
        apply_commit(&mut state, staged);
        assert_eq!(state.entries.len(), 4);
        assert!(!state.runs[&run.id].pipelines[&(7, 1)].delivered());
        let duplicate = prepare_commit(&state, &run, &commit, clock.now(), 1).unwrap();
        apply_commit(&mut state, duplicate);
        assert_eq!(state.sequence, 4);
        assert_eq!(state.entries.len(), 4);
    }

    #[tokio::test]
    async fn sequence_exhaustion_and_capacity_reject_without_partial_mutation() {
        let (_, clock, run, lease) = fixture(RetentionMode::Standard).await;
        let mut state = ReportState {
            sequence: u64::try_from(i64::MAX).unwrap(),
            ..ReportState::default()
        };
        assert!(matches!(
            prepare_facts(&state, &run, &[fact(&lease, clock.now(), 1)], clock.now()),
            Err(StoreError::Conflict(_))
        ));
        assert!(state.entries.is_empty());
        state.sequence = 0;
        let facts = (0..MAX_FACTS_PER_RUN)
            .map(|ordinal| fact(&lease, clock.now(), u64::try_from(ordinal).unwrap()))
            .collect::<Vec<_>>();
        let prepared = prepare_facts(&state, &run, &facts, clock.now()).unwrap();
        apply_commit(&mut state, prepared);
        assert_eq!(state.entries.len(), MAX_FACTS_PER_RUN);
        assert!(matches!(
            prepare_facts(&state, &run, &[fact(&lease, clock.now(), 70_000)], clock.now()),
            Err(StoreError::Conflict(_))
        ));
        assert!(prepare_facts(&state, &run, &facts[..1], clock.now()).is_ok());
        assert_eq!(state.purge_run(run.id), u64::try_from(MAX_FACTS_PER_RUN).unwrap());
        assert!(state.entries.is_empty());
        assert_eq!(state.sequence, u64::try_from(MAX_FACTS_PER_RUN).unwrap());
    }

    #[tokio::test]
    async fn ack_needs_all_outboxes_and_parse_evidence_and_is_idempotent() {
        let (_, clock, run, lease) = fixture(RetentionMode::Standard).await;
        let facts = [
            pipeline(
                &lease,
                clock.now(),
                1,
                PipelineStageV1::Fetch,
                PipelineStateV1::Succeeded,
            ),
            pipeline(
                &lease,
                clock.now(),
                2,
                PipelineStageV1::Parse,
                PipelineStateV1::Succeeded,
            ),
            pipeline(
                &lease,
                clock.now(),
                3,
                PipelineStageV1::Index,
                PipelineStateV1::Pending,
            ),
            pipeline(
                &lease,
                clock.now(),
                4,
                PipelineStageV1::Completion,
                PipelineStateV1::Pending,
            ),
        ];
        let mut state = ReportState::default();
        let prepared = prepare_facts(&state, &run, &facts, clock.now()).unwrap();
        apply_commit(&mut state, prepared);
        let incomplete = prepare_delivery_ack(&state, &run, 7, false, clock.now()).unwrap();
        apply_commit(&mut state, incomplete);
        assert!(!state.runs[&run.id].pipelines[&(7, 1)].delivered());
        let prepared = prepare_delivery_ack(&state, &run, 7, true, clock.now()).unwrap();
        assert_eq!(state.entries.len(), 4);
        assert!(!state.runs[&run.id].pipelines[&(7, 1)].delivered());
        apply_commit(&mut state, prepared);
        assert_eq!(state.entries.len(), 6);
        assert!(state.runs[&run.id].pipelines[&(7, 1)].delivered());
        clock.advance_ms(1);
        let replay = prepare_delivery_ack(&state, &run, 7, true, clock.now()).unwrap();
        apply_commit(&mut state, replay);
        assert_eq!(state.entries.len(), 6);
    }

    #[tokio::test]
    async fn fresh_ack_recovers_delivery_failure_but_never_invents_parse_evidence() {
        use crawlx_core::report_history::{ProcessorIdentityV1, ProcessorStageV1, StageOutcomeV1};
        let (_, clock, run, lease) = fixture(RetentionMode::Standard).await;
        let fetch = pipeline(
            &lease,
            clock.now(),
            1,
            PipelineStageV1::Fetch,
            PipelineStateV1::Succeeded,
        );
        let mut state = ReportState::default();
        let prepared = prepare_facts(&state, &run, &[fetch], clock.now()).unwrap();
        apply_commit(&mut state, prepared);
        let missing = prepare_delivery_ack(&state, &run, 7, true, clock.now()).unwrap();
        apply_commit(&mut state, missing);
        assert_eq!(state.entries.len(), 1);
        let parse = pipeline(
            &lease,
            clock.now(),
            2,
            PipelineStageV1::Parse,
            PipelineStateV1::Succeeded,
        );
        let mut failure = fact(&lease, clock.now(), 3);
        failure.request_id = Some(7);
        failure.data = ReportDataV1::Stage {
            stage: ProcessorStageV1::Delivery,
            outcome: StageOutcomeV1::Failed,
            duration_us: 1,
            processor: ProcessorIdentityV1::Delivery,
            processor_version: 1,
        };
        let prepared = prepare_facts(&state, &run, &[parse, failure], clock.now()).unwrap();
        apply_commit(&mut state, prepared);
        let incomplete = prepare_delivery_ack(&state, &run, 7, false, clock.now()).unwrap();
        apply_commit(&mut state, incomplete);
        assert!(!state.runs[&run.id].pipelines[&(7, 1)].delivered());
        let ack = prepare_delivery_ack(&state, &run, 7, true, clock.now()).unwrap();
        apply_commit(&mut state, ack);
        assert_eq!(state.entries.len(), 5);
        assert!(state.runs[&run.id].pipelines[&(7, 1)].delivered());
        assert!(state.entries.values().any(|fact| matches!(
            fact.data,
            ReportDataV1::Stage {
                outcome: StageOutcomeV1::Failed,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn final_real_outbox_ack_rolls_back_on_report_error_and_replays_once() {
        use crawlx_core::dataset::{
            AcceptedBatchV1, AcceptedItemV1, DatasetContentV1, DeliveryBatchV1, DeliveryOutboxRepo,
            DeliveryStateV1,
        };
        let (store, clock, mut run, lease) = fixture(RetentionMode::Standard).await;
        run.config.datasets = serde_json::from_value(serde_json::json!({
            "version": 1,
            "stores": [{"name":"items","schemaVersion":"document_item_v1","maxItems":20,"maxBytes":1048576}],
            "feeds": [
                {"id":"first","source":"items","serializer":"jsonl","serializerVersion":1,
                 "destination":"fixture","maxBatchItems":10,"maxBatchBytes":1048576},
                {"id":"second","source":"items","serializer":"jsonl","serializerVersion":1,
                 "destination":"fixture","maxBatchItems":10,"maxBatchBytes":1048576}
            ]
        }))
        .unwrap();
        let content = DatasetContentV1::Durable {
            artifact: crawlx_core::ArtifactRef {
                id: crawlx_core::ArtifactId::new(),
                digest: Digest::of("crawlx/report-ack-test", b"{}\n"),
            },
        };
        let item = AcceptedItemV1::new(
            "item".into(),
            "fixture_v1".into(),
            "document_item_v1".into(),
            "fixture_v1".into(),
            content.clone(),
            3,
        );
        let accepted = [AcceptedBatchV1::new("items".into(), vec![item])];
        let outboxes = ["first", "second"].map(|feed| {
            DeliveryBatchV1::for_request(
                feed.into(),
                format!("request.7.{feed}"),
                content.clone(),
                3,
                clock.now() + ChronoDuration::hours(1),
            )
        });
        {
            let mut g = store.inner.lock();
            g.runs.get_mut(&run.id).unwrap().config.datasets = run.config.datasets.clone();
            let prepared =
                crate::dataset::prepare_memory(&g.dataset, &run, 7, &accepted, &[], &outboxes, clock.now())
                    .unwrap();
            crate::dataset::apply_prepared(&mut g.dataset, prepared);
            let original_batches = g
                .dataset
                .deliveries
                .values()
                .map(|row| row.receipt.batch.clone())
                .collect::<Vec<_>>();
            assert!(crate::dataset::prepare_memory(
                &g.dataset, &run, 8, &[], &[], &original_batches, clock.now(),
            ).is_err(), "one outbox identity cannot change source request");
        }
        for (ordinal, stage, state) in [
            (1, PipelineStageV1::Fetch, PipelineStateV1::Succeeded),
            (2, PipelineStageV1::Parse, PipelineStateV1::Succeeded),
            (3, PipelineStageV1::Index, PipelineStateV1::Pending),
            (4, PipelineStageV1::Completion, PipelineStateV1::Pending),
        ] {
            store
                .append_fact(&lease, &pipeline(&lease, clock.now(), ordinal, stage, state))
                .await
                .unwrap();
        }
        let mut claims = store.claim(run.id, lease.worker, 2, 60).await.unwrap();
        assert_eq!(claims.len(), 2);
        store
            .acknowledge(run.id, claims[0].id, claims[0].fence)
            .await
            .unwrap();
        assert!(!store.report_history.lock().runs[&run.id].pipelines[&(7, 1)].delivered());
        let failed_index = pipeline(
            &lease,
            clock.now(),
            98,
            PipelineStageV1::Index,
            PipelineStateV1::Failed,
        );
        store.append_fact(&lease, &failed_index).await.unwrap();
        store
            .retry(run.id, claims[1].id, claims[1].fence, clock.now())
            .await
            .unwrap();
        let mut retried = store.claim(run.id, lease.worker, 1, 60).await.unwrap();
        assert_eq!(retried.len(), 1);
        assert!(retried[0].fence > claims[1].fence);
        claims[1] = retried.remove(0);
        assert!(!store.report_history.lock().runs[&run.id].pipelines[&(7, 1)].delivered());
        let sequence = store.report_history.lock().sequence;
        store.report_history.lock().sequence = u64::try_from(i64::MAX).unwrap();
        assert!(store
            .acknowledge(run.id, claims[1].id, claims[1].fence)
            .await
            .is_err());
        assert_eq!(
            store.inner.lock().dataset.deliveries[&claims[1].id].receipt.state,
            DeliveryStateV1::Leased,
        );
        assert!(!store.report_history.lock().runs[&run.id].pipelines[&(7, 1)].delivered());
        store.report_history.lock().sequence = sequence;
        store
            .acknowledge(run.id, claims[1].id, claims[1].fence)
            .await
            .unwrap();
        assert!(store.report_history.lock().runs[&run.id].pipelines[&(7, 1)].delivered());
        assert_eq!(store.report_history.lock().entries.len(), 7);
        assert!(store
            .report_history
            .lock()
            .entries
            .values()
            .any(|fact| fact == &failed_index));
        clock.advance_ms(1);
        store
            .acknowledge(run.id, claims[1].id, claims[1].fence)
            .await
            .unwrap();
        assert_eq!(store.report_history.lock().entries.len(), 7);
        let mut failed = fact(&lease, clock.now(), 99);
        failed.request_id = Some(7);
        failed.data = ReportDataV1::Stage {
            stage: crawlx_core::report_history::ProcessorStageV1::Delivery,
            outcome: crawlx_core::report_history::StageOutcomeV1::Failed,
            duration_us: 1,
            processor: crawlx_core::report_history::ProcessorIdentityV1::Delivery,
            processor_version: 1,
        };
        store.append_fact(&lease, &failed).await.unwrap();
        store
            .acknowledge(run.id, claims[1].id, claims[1].fence)
            .await
            .unwrap();
        assert!(!store.report_history.lock().runs[&run.id].pipelines[&(7, 1)].delivered());
        assert_eq!(store.report_history.lock().entries.len(), 8);
    }

    #[tokio::test]
    async fn url_facts_bind_real_attempt_owner_and_request_without_requiring_request_diagnostics() {
        let (store, clock, run, session) = fixture(RetentionMode::Standard).await;
        store.inner.lock().runs.get_mut(&run.id).unwrap().config.mode = crawlx_core::CrawlMode::Static;
        let (entry, fence) = store
            .lease_one_fenced(run.id, session.worker, 7)
            .await
            .unwrap()
            .unwrap();
        let lease = CustodyLease::for_url(run.tenant, run.id, entry.id, session.worker, fence);
        let mut evidence = fact(&lease, clock.now(), 1);
        evidence.attempt = entry.attempts;
        store.append_fact(&lease, &evidence).await.unwrap();
        let mut wrong_attempt = fact(&lease, clock.now(), 2);
        wrong_attempt.attempt = entry.attempts.saturating_add(1);
        assert!(matches!(
            store.append_fact(&lease, &wrong_attempt).await,
            Err(StoreError::LeaseLost)
        ));
        let mut wrong_request = fact(&lease, clock.now(), 3);
        wrong_request.request_id = Some(6);
        assert!(matches!(
            store.append_fact(&lease, &wrong_request).await,
            Err(StoreError::LeaseLost)
        ));
        let mut wrong_owner = lease.clone();
        wrong_owner.worker = WorkerId::new();
        assert!(matches!(
            store.append_fact(&wrong_owner, &evidence).await,
            Err(StoreError::LeaseLost)
        ));
        let mut session_fact = fact(&session, clock.now(), 4);
        session_fact.request_id = Some(99);
        assert!(matches!(
            store.append_fact(&session, &session_fact).await,
            Err(StoreError::LeaseLost)
        ));
        assert_eq!(store.report_history.lock().entries.len(), 1);
    }

    #[tokio::test]
    async fn live_authorization_revocation_blocks_even_idempotent_fact_replay() {
        struct Denied;
        #[async_trait]
        impl HeadResponseAuthorizer for Denied {
            async fn authorize(
                &self,
                _: CrawlRunId,
                _: TenantId,
                _: crawlx_core::AuthorizationRecordId,
                _: Timestamp,
            ) -> Result<(), StoreError> {
                Err(StoreError::AccessDenied("test authorization revoked".into()))
            }
        }
        let (store, clock, run, lease) = fixture(RetentionMode::Standard).await;
        let evidence = fact(&lease, clock.now(), 1);
        store.append_fact(&lease, &evidence).await.unwrap();
        store
            .inner
            .lock()
            .runs
            .get_mut(&run.id)
            .unwrap()
            .config
            .safety
            .authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        store.set_head_response_authorizer(Arc::new(Denied));
        assert!(matches!(
            store.append_fact(&lease, &evidence).await,
            Err(StoreError::AccessDenied(_))
        ));
        assert_eq!(store.report_history.lock().entries.len(), 1);
    }
}
