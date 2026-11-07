//! Memory frontier transaction helpers; same bounds and fence semantics as PostgreSQL.
use super::*;
use crawlx_core::acquisition::{AcquisitionAllowanceV1, AcquisitionUsageV1};
use crawlx_core::orchestration::*;
use crawlx_core::request::{RequestEnvelopeV1, RequestIdentityV1};

#[derive(Clone, Default)]
pub(super) struct RequestState {
    envelopes: BTreeMap<i64, (RequestEnvelopeV1, RequestIdentityV1, u64)>,
    identities: BTreeMap<(CrawlRunId, Digest, u32), i64>,
    envelope_bytes: BTreeMap<i64, u64>,
    principals: BTreeMap<i64, String>,
    effects: BTreeMap<i64, u32>,
    effect_escrows: BTreeMap<i64, (i64, u32, Option<u32>)>,
    created: BTreeMap<i64, Timestamp>,
    acquisition: BTreeMap<i64, AcquisitionEscrow>,
    producers: BTreeMap<CrawlRunId, (u64, bool)>,
    cursors: BTreeMap<(CrawlRunId, String), LoaderCursorV1>,
    receipts: BTreeMap<(CrawlRunId, Digest), (Digest, RequestBatchReceiptV1)>,
}

#[derive(Clone)]
struct AcquisitionEscrow {
    deadline: Timestamp,
    usage: AcquisitionUsageV1,
    fence: i64,
    receipt: AcquisitionAllowanceV1,
    settlement: Option<AcquisitionUsageV1>,
}

fn config(run: &CrawlRun) -> Result<OrchestrationConfigV1, StoreError> {
    let config = run.config.orchestration.clone().unwrap_or_default();
    config.validate()?;
    Ok(config)
}
fn live_parent(g: &Inner, run: CrawlRunId, id: i64, fence: i64, now: Timestamp) -> bool {
    g.frontier.iter().any(|row| {
        row.e.id == id
            && row.e.run == run
            && row.e.status == FrontierStatus::Leased
            && row.token == Some(fence)
            && row.expires.is_some_and(|expires| expires > now)
    })
}

pub(super) fn reserve_legacy(
    g: &Inner,
    run: CrawlRunId,
    envelope: &RequestEnvelopeV1,
    status: FrontierStatus,
) -> Result<u64, StoreError> {
    let run_record = g.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
    let cfg = config(run_record)?;
    let size = u64::try_from(serde_json::to_vec(envelope)?.len())
        .map_err(|_| StoreError::Conflict("request size overflow".into()))?;
    if status != FrontierStatus::Pending {
        return Ok(size);
    }
    let mut entries = 0_u64;
    let mut bytes = size;
    for row in g.frontier.iter().filter(|row| {
        row.e.run == run && matches!(row.e.status, FrontierStatus::Pending | FrontierStatus::Leased)
    }) {
        entries = entries.saturating_add(1);
        bytes = bytes.saturating_add(g.requests.envelope_bytes.get(&row.e.id).copied().unwrap_or(0));
    }
    if entries >= cfg.queue.max_pending_entries || bytes > cfg.queue.max_pending_envelope_bytes {
        return Err(StoreError::Conflict("frontier quota exhausted".into()));
    }
    Ok(size)
}

pub(super) fn record_legacy(
    g: &mut Inner,
    run: CrawlRunId,
    id: i64,
    envelope: RequestEnvelopeV1,
    bytes: u64,
    now: Timestamp,
) {
    let identity = RequestIdentityV1::stored(envelope.url.key, 1, 0);
    g.requests.identities.insert((run, identity.key, 0), id);
    g.requests.envelope_bytes.insert(id, bytes);
    g.requests.envelopes.insert(id, (envelope, identity, 1));
    g.requests.principals.insert(id, "anonymous".into());
    g.requests.created.insert(id, now);
}

pub(super) fn known(g: &Inner, run: CrawlRunId, key: Digest, generation: u32) -> bool {
    g.requests.identities.contains_key(&(run, key, generation))
}
pub(super) fn priority(g: &Inner, id: i64) -> i32 {
    g.requests
        .envelopes
        .get(&id)
        .map_or(0, |(envelope, _, _)| envelope.priority)
}

pub(super) fn append(
    g: &mut Inner,
    batch: &RequestBatchV1,
    now: Timestamp,
    recrawl: bool,
) -> Result<RequestBatchReceiptV1, StoreError> {
    batch.validate()?;
    let digest = Digest::of_value("crawlx/request-batch/v1", batch)
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    let run = g.runs.get(&batch.run).ok_or_else(|| nf("crawl run", batch.run))?;
    if run.tenant != batch.tenant {
        return Err(StoreError::AccessDenied("request tenant mismatch".into()));
    }
    if let Some((stored, receipt)) = g.requests.receipts.get(&(batch.run, batch.batch_id)) {
        return if *stored == digest {
            Ok(receipt.clone())
        } else {
            Err(StoreError::Conflict(
                "batch id reused with different content".into(),
            ))
        };
    }
    if !matches!(
        run.status,
        RunStatus::Queued | RunStatus::Running | RunStatus::Paused
    ) || run.started_at.unwrap_or(run.created_at)
        + ChronoDuration::seconds(i64::from(run.config.limits.duration_seconds))
        <= now
    {
        return Err(StoreError::AccessDenied("run no longer admits requests".into()));
    }
    if batch.principal != "anonymous"
        && !g
            .sessions
            .values()
            .any(|session| session.s.run == batch.run && session.s.role.0 == batch.principal)
    {
        return Err(StoreError::AccessDenied("request principal unavailable".into()));
    }
    let cfg = config(run)?;
    if batch.requests.len() > usize::try_from(cfg.queue.batch_size).unwrap_or(0) {
        return Err(StoreError::Conflict("configured request batch limit".into()));
    }
    let (epoch, sealed) = g
        .requests
        .producers
        .get(&batch.run)
        .copied()
        .unwrap_or((1, false));
    if batch.producer_epoch != epoch || (sealed && batch.parent_fence.is_none()) {
        return Err(StoreError::Conflict("producer epoch closed or stale".into()));
    }
    if let Some((id, fence)) = batch.parent_fence {
        if !live_parent(g, batch.run, id, fence, now) {
            return Err(StoreError::LeaseLost);
        }
    }
    if let Some(next) = &batch.next_cursor {
        if g.requests.cursors.get(&(batch.run, next.source.clone())) != batch.expected_cursor.as_ref() {
            return Err(StoreError::Conflict("loader cursor changed".into()));
        }
    }
    let mut receipt = RequestBatchReceiptV1::empty(batch.next_cursor.clone());
    let mut staged = Vec::with_capacity(batch.requests.len());
    let mut keys = std::collections::BTreeSet::new();
    let mut bytes = 0_u64;
    for envelope in &batch.requests {
        if envelope.revisit_generation != 0 && !recrawl {
            return Err(StoreError::AccessDenied(
                "revisit requires recrawl transaction".into(),
            ));
        }
        let identity = envelope
            .identity(batch.tenant, batch.run, &batch.principal, &BTreeMap::new(), 1)
            .map_err(|e| StoreError::Conflict(e.to_string()))?;
        if known(g, batch.run, identity.key, identity.revisit_generation)
            || !keys.insert((identity.key, identity.revisit_generation))
        {
            receipt.duplicates = receipt.duplicates.saturating_add(1);
            continue;
        }
        let size = u64::try_from(serde_json::to_vec(envelope)?.len())
            .map_err(|_| StoreError::Conflict("request size overflow".into()))?;
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| StoreError::Conflict("request size overflow".into()))?;
        staged.push((envelope.clone(), identity, size));
    }
    let mut open = 0_u64;
    let mut open_bytes = 0_u64;
    for row in &g.frontier {
        if recrawl && batch.parent_fence.is_some_and(|(id, _)| id == row.e.id) {
            continue;
        }
        if row.e.run == batch.run && matches!(row.e.status, FrontierStatus::Pending | FrontierStatus::Leased)
        {
            open = open.saturating_add(1);
            open_bytes =
                open_bytes.saturating_add(g.requests.envelope_bytes.get(&row.e.id).copied().unwrap_or(0));
        }
    }
    let extra_entries = if batch.initial_denial.is_none() {
        u64::try_from(staged.len()).unwrap_or(u64::MAX)
    } else {
        0
    };
    let extra_bytes = if batch.initial_denial.is_none() { bytes } else { 0 };
    if open.saturating_add(extra_entries) > cfg.queue.max_pending_entries
        || open_bytes.saturating_add(extra_bytes) > cfg.queue.max_pending_envelope_bytes
    {
        return Err(StoreError::Conflict("frontier quota exhausted".into()));
    }
    g.next_frontier_id
        .checked_add(
            i64::try_from(staged.len()).map_err(|_| StoreError::Conflict("frontier id overflow".into()))?,
        )
        .ok_or_else(|| StoreError::Conflict("frontier id overflow".into()))?;
    for (envelope, identity, size) in staged {
        g.next_frontier_id += 1;
        let id = g.next_frontier_id;
        g.frontier.push(FrontierRow {
            e: FrontierEntry {
                id,
                run: batch.run,
                url: envelope.url.clone(),
                depth: envelope.depth,
                status: batch
                    .initial_denial
                    .as_ref()
                    .map_or(FrontierStatus::Pending, |(status, _)| *status),
                denial_reason: batch.initial_denial.as_ref().map(|(_, reason)| reason.clone()),
                attempts: 0,
                discovered_from: envelope.parent,
            },
            key: identity.key,
            strategy_score: crawlx_core::priority::priority_depth(
                &envelope.url.url,
                u32::from(envelope.depth),
                envelope.method == "GET",
            ),
            owner: None,
            token: None,
            expires: None,
            next_attempt_at: envelope.not_before.unwrap_or(now),
        });
        g.requests
            .identities
            .insert((batch.run, identity.key, identity.revisit_generation), id);
        g.requests.envelope_bytes.insert(id, size);
        g.requests.envelopes.insert(id, (envelope, identity, 1));
        g.requests.principals.insert(id, batch.principal.clone());
        g.requests.created.insert(id, now);
        receipt.inserted.push(id);
    }
    if let Some(cursor) = &batch.next_cursor {
        g.requests
            .cursors
            .insert((batch.run, cursor.source.clone()), cursor.clone());
    }
    g.requests.producers.entry(batch.run).or_insert((epoch, false));
    g.requests
        .receipts
        .insert((batch.run, batch.batch_id), (digest, receipt.clone()));
    Ok(receipt)
}

impl MemoryStore {
    pub(super) fn acquisition_worker_ready(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        policy: Option<&crawlx_core::acquisition::AcquisitionPolicyV1>,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        let Some(policy) = policy else {
            return Ok(true);
        };
        policy
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let registry = self.worker_registry.lock();
        Ok(registry.rows.get(&worker).is_some_and(|(row, backends)| {
            !row.draining
                && row.last_heartbeat_at <= now
                && row.last_heartbeat_at >= now - ChronoDuration::seconds(90)
                && (row.capacity.get("acceptsQueued") == Some(&serde_json::Value::Bool(true))
                    || row
                        .capacity
                        .get("localRun")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| value.parse::<CrawlRunId>().ok())
                        == Some(run))
                && policy.backend_ids.iter().all(|id| {
                    backends
                        .iter()
                        .any(|backend| backend.available && backend.backend_id == *id)
                })
        }))
    }
    pub(super) async fn request_append(
        &self,
        batch: RequestBatchV1,
    ) -> Result<RequestBatchReceiptV1, StoreError> {
        append(&mut self.inner.lock(), &batch, self.clock.now(), false)
    }
    pub(super) async fn request_page(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<FrontierEntry>, StoreError> {
        if limit == 0 || limit > 1000 {
            return Err(StoreError::Conflict("invalid frontier page limit".into()));
        }
        Ok(self
            .inner
            .lock()
            .frontier
            .iter()
            .filter(|row| row.e.run == run && row.e.id > after)
            .take(usize::try_from(limit).unwrap_or(1000))
            .map(|row| row.e.clone())
            .collect())
    }
    pub(super) async fn request_metadata_page(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<RequestMetadataV1>, StoreError> {
        if limit == 0 || limit > 1000 {
            return Err(StoreError::Conflict("invalid frontier page limit".into()));
        }
        let g = self.inner.lock();
        Ok(g.frontier
            .iter()
            .filter(|row| row.e.run == run && row.e.id > after)
            .take(usize::try_from(limit).unwrap_or(1000))
            .map(|row| {
                RequestMetadataV1::new(
                    row.e.id,
                    row.e.status,
                    row.e.depth,
                    row.e.attempts,
                    g.requests
                        .envelopes
                        .get(&row.e.id)
                        .map_or(0, |(_, identity, _)| identity.revisit_generation),
                )
            })
            .collect())
    }
    pub(super) async fn request_retry(
        &self,
        id: i64,
        fence: i64,
        not_before: Timestamp,
    ) -> Result<bool, StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        let index = g
            .frontier
            .iter()
            .position(|row| row.e.id == id)
            .ok_or_else(|| nf("frontier row", id))?;
        let run_id = g.frontier[index].e.run;
        if !live_parent(&g, run_id, id, fence, now) {
            return Err(StoreError::LeaseLost);
        }
        let run = g.runs.get(&run_id).ok_or_else(|| nf("crawl run", run_id))?;
        let cfg = config(run)?;
        let created = g.requests.created.get(&id).copied().unwrap_or(run.created_at);
        let deadline = created
            + ChronoDuration::milliseconds(i64::try_from(cfg.attempts.max_elapsed_ms).unwrap_or(i64::MAX));
        let native_exhausted = run
            .config
            .acquisition
            .as_ref()
            .zip(g.requests.acquisition.get(&id))
            .is_some_and(|(policy, escrow)| {
                not_before >= escrow.deadline
                    || escrow.usage.attempts_reserved >= policy.max_attempts
                    || escrow.usage.network_requests_reserved >= policy.max_network_requests
                    || escrow.usage.decoded_bytes_reserved
                        >= policy.max_decoded_bytes.min(run.config.fetch.max_response_bytes)
            });
        let exhausted = u32::from(g.frontier[index].e.attempts) >= cfg.attempts.max_total_effects
            || g.requests.effects.get(&id).copied().unwrap_or(0) >= cfg.attempts.max_total_effects
            || not_before >= deadline
            || native_exhausted;
        let row = &mut g.frontier[index];
        row.e.status = if exhausted {
            FrontierStatus::Failed
        } else {
            FrontierStatus::Pending
        };
        if exhausted {
            row.e.denial_reason = Some("effect_budget_exhausted".into());
        }
        row.next_attempt_at = row.next_attempt_at.max(not_before);
        row.owner = None;
        row.expires = None;
        Ok(!exhausted)
    }
    pub(super) async fn request_reserve(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        effects: u32,
    ) -> Result<(), StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        if !live_parent(&g, run, id, fence, now) {
            return Err(StoreError::LeaseLost);
        }
        if g.requests
            .effect_escrows
            .get(&id)
            .is_some_and(|(held, _, _)| *held == fence)
        {
            return Err(StoreError::Conflict(
                "effects already reserved by this lease".into(),
            ));
        }
        let record = g.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
        let cfg = config(record)?;
        let created = g.requests.created.get(&id).copied().unwrap_or(record.created_at);
        if created
            + ChronoDuration::milliseconds(i64::try_from(cfg.attempts.max_elapsed_ms).unwrap_or(i64::MAX))
            <= now
        {
            return Err(StoreError::Conflict("request deadline exhausted".into()));
        }
        let next = g
            .requests
            .effects
            .get(&id)
            .copied()
            .unwrap_or(0)
            .checked_add(effects)
            .filter(|next| *next <= cfg.attempts.max_total_effects)
            .ok_or_else(|| StoreError::Conflict("request effect budget exhausted".into()))?;
        if effects == 0 {
            return Err(StoreError::Conflict("empty effect reservation".into()));
        }
        g.requests.effects.insert(id, next);
        g.requests.effect_escrows.insert(id, (fence, effects, None));
        Ok(())
    }
    pub(super) async fn request_settle_effects(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        reserved: u32,
        actual: u32,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        if !live_parent(&g, run, id, fence, self.clock.now()) {
            return Err(StoreError::LeaseLost);
        }
        let (held, amount, settled) = g
            .requests
            .effect_escrows
            .get(&id)
            .copied()
            .ok_or(StoreError::LeaseLost)?;
        if held != fence || amount != reserved || actual > reserved {
            return Err(StoreError::Conflict(
                "effect settlement exceeds lease escrow".into(),
            ));
        }
        if let Some(prior) = settled {
            return if prior == actual {
                Ok(())
            } else {
                Err(StoreError::Conflict("effect settlement changed".into()))
            };
        }
        let effects = g
            .requests
            .effects
            .get(&id)
            .copied()
            .unwrap_or(0)
            .checked_sub(reserved - actual)
            .ok_or_else(|| StoreError::Conflict("effect settlement mismatch".into()))?;
        g.requests.effects.insert(id, effects);
        g.requests
            .effect_escrows
            .insert(id, (fence, reserved, Some(actual)));
        Ok(())
    }
    pub(super) async fn acquisition_reserve(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
    ) -> Result<AcquisitionAllowanceV1, StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        if !live_parent(&g, run, id, fence, now) {
            return Err(StoreError::LeaseLost);
        }
        let record = g.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
        let policy = record
            .config
            .acquisition
            .as_ref()
            .ok_or_else(|| StoreError::Conflict("native acquisition policy required".into()))?;
        policy
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let request_created = g.requests.created.get(&id).copied().unwrap_or(record.created_at);
        let request_ms = record
            .config
            .orchestration
            .as_ref()
            .map_or(u64::from(policy.max_elapsed_ms), |cfg| {
                cfg.attempts.max_elapsed_ms
            });
        let elapsed = policy.max_elapsed_ms.min(
            record
                .config
                .scrape
                .as_ref()
                .map_or(policy.max_elapsed_ms, |job| job.options.timeout_ms),
        );
        let absolute = (now + ChronoDuration::milliseconds(i64::from(elapsed)))
            .min(
                request_created + ChronoDuration::milliseconds(i64::try_from(request_ms).unwrap_or(i64::MAX)),
            )
            .min(
                record.started_at.unwrap_or(record.created_at)
                    + ChronoDuration::seconds(i64::from(record.config.limits.duration_seconds)),
            );
        let (deadline, previous) = match g.requests.acquisition.get(&id) {
            Some(escrow) if escrow.fence == fence => {
                return Err(StoreError::Conflict(
                    "acquisition already reserved by this lease".into(),
                ))
            }
            Some(escrow) => (escrow.deadline, escrow.usage.clone()),
            None => (absolute, AcquisitionUsageV1::default()),
        };
        let maximum = record
            .config
            .orchestration
            .as_ref()
            .map_or(u32::MAX, |cfg| cfg.attempts.max_total_effects);
        let reserved = g.requests.effects.get(&id).copied().unwrap_or(0);
        let mut receipt = AcquisitionAllowanceV1::remaining(policy, previous, deadline, now)?;
        receipt.remaining_network_requests = receipt
            .remaining_network_requests
            .min(maximum.saturating_sub(reserved));
        let bytes = policy
            .max_decoded_bytes
            .min(record.config.fetch.max_response_bytes)
            .saturating_sub(receipt.previous_usage.decoded_bytes_reserved);
        receipt.remaining_decoded_bytes = receipt.remaining_decoded_bytes.min(bytes);
        if receipt.remaining_decoded_bytes == 0 {
            return Err(StoreError::Conflict(
                "parent decoded byte allowance exhausted".into(),
            ));
        }
        if receipt.remaining_network_requests == 0 {
            return Err(StoreError::Conflict("request effect budget exhausted".into()));
        }
        g.requests
            .effects
            .insert(id, reserved.saturating_add(receipt.remaining_network_requests));
        g.requests.acquisition.insert(
            id,
            AcquisitionEscrow {
                deadline,
                usage: receipt.held_usage(),
                fence,
                receipt: receipt.clone(),
                settlement: None,
            },
        );
        Ok(receipt)
    }
    pub(super) async fn acquisition_settle(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        usage: &AcquisitionUsageV1,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        if !live_parent(&g, run, id, fence, self.clock.now()) {
            return Err(StoreError::LeaseLost);
        }
        let escrow = g
            .requests
            .acquisition
            .get(&id)
            .filter(|escrow| escrow.fence == fence)
            .ok_or_else(|| StoreError::Conflict("acquisition escrow missing".into()))?;
        if let Some(previous) = &escrow.settlement {
            return if previous == usage {
                Ok(())
            } else {
                Err(StoreError::Conflict("acquisition settlement changed".into()))
            };
        }
        let settled = escrow.receipt.checked_settlement(usage)?;
        let refund = escrow
            .receipt
            .remaining_network_requests
            .saturating_sub(usage.network_requests_reserved);
        let reserved = g
            .requests
            .effects
            .get(&id)
            .copied()
            .unwrap_or(0)
            .checked_sub(refund)
            .ok_or_else(|| StoreError::Conflict("acquisition effect settlement mismatch".into()))?;
        let escrow = g.requests.acquisition.get_mut(&id).ok_or(StoreError::LeaseLost)?;
        escrow.usage = settled;
        escrow.settlement = Some(usage.clone());
        g.requests.effects.insert(id, reserved);
        Ok(())
    }
    pub(super) async fn request_get(&self, run: CrawlRunId, id: i64) -> Result<QueuedRequestV1, StoreError> {
        let g = self.inner.lock();
        let row = g
            .frontier
            .iter()
            .find(|row| row.e.run == run && row.e.id == id)
            .ok_or_else(|| nf("frontier row", id))?;
        let (envelope, identity, state_version) = match g.requests.envelopes.get(&id) {
            Some(stored) => stored.clone(),
            None => (
                RequestEnvelopeV1::get(row.e.url.clone(), row.e.depth, row.e.discovered_from),
                RequestIdentityV1::stored(row.key, 1, 0),
                1,
            ),
        };
        Ok(QueuedRequestV1::stored(
            row.e.clone(),
            envelope,
            identity,
            state_version,
            g.requests
                .principals
                .get(&id)
                .cloned()
                .unwrap_or_else(|| "anonymous".into()),
        ))
    }
    pub(super) async fn request_seal(&self, run: CrawlRunId, expected_epoch: u64) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        if !g.runs.contains_key(&run) {
            return Err(nf("crawl run", run));
        }
        let producer = g.requests.producers.entry(run).or_insert((1, false));
        if producer.0 != expected_epoch {
            return Err(StoreError::Conflict("stale producer epoch".into()));
        }
        producer.1 = true;
        Ok(())
    }
    pub(super) async fn request_activity(&self, run: CrawlRunId) -> Result<FrontierActivityV1, StoreError> {
        let g = self.inner.lock();
        let now = self.clock.now();
        let mut pending = false;
        let mut leased = false;
        for row in g.frontier.iter().filter(|row| row.e.run == run) {
            match row.e.status {
                FrontierStatus::Pending if row.next_attempt_at <= now => {
                    return Ok(FrontierActivityV1::Ready)
                }
                FrontierStatus::Pending => pending = true,
                FrontierStatus::Leased => leased = true,
                _ => {}
            }
        }
        if pending {
            return Ok(FrontierActivityV1::WaitingCooldown);
        }
        if leased {
            return Ok(FrontierActivityV1::Draining);
        }
        let continuous = g
            .runs
            .get(&run)
            .and_then(|run| run.config.orchestration.as_ref())
            .is_some_and(|cfg| cfg.queue.producer_mode == ProducerModeV1::Continuous);
        let sealed = g
            .requests
            .producers
            .get(&run)
            .map_or(!continuous, |(_, sealed)| *sealed);
        Ok(if sealed {
            FrontierActivityV1::Terminal
        } else {
            FrontierActivityV1::WaitingProducer
        })
    }
    pub(super) async fn request_cursor(
        &self,
        run: CrawlRunId,
        source: &str,
    ) -> Result<Option<LoaderCursorV1>, StoreError> {
        Ok(self
            .inner
            .lock()
            .requests
            .cursors
            .get(&(run, source.to_owned()))
            .cloned())
    }
}

#[async_trait]
impl RequestCommitRepo for MemoryStore {
    async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError> {
        self.validate_dataset_results(commit.run, &commit.accepted, &commit.state_deltas, &commit.outbox)
            .await?;
        let now = self.clock.now();
        let mut g = self.inner.lock();
        if !live_parent(&g, commit.run, commit.request_id, commit.fence, now) {
            return Err(StoreError::LeaseLost);
        }
        let parent_index = g
            .frontier
            .iter()
            .position(|row| row.e.id == commit.request_id)
            .ok_or(StoreError::LeaseLost)?;
        if matches!(commit.status, FrontierStatus::Pending | FrontierStatus::Leased)
            || commit.reason.as_deref().is_some_and(|reason| {
                reason.len() > 128
                    || !reason
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
            })
        {
            return Err(StoreError::Conflict("invalid request disposition".into()));
        }
        let version = g
            .requests
            .envelopes
            .get(&commit.request_id)
            .map_or(1, |(_, _, version)| *version);
        if version != commit.expected_state_version {
            return Err(StoreError::Conflict("request state version changed".into()));
        }
        let run = g
            .runs
            .get(&commit.run)
            .ok_or_else(|| nf("crawl run", commit.run))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
        }
        if let Some(page) = &commit.page {
            if page.run != commit.run
                || page.frontier_id != commit.request_id
                || page.url.key != g.frontier[parent_index].e.url.key
                || commit.status != FrontierStatus::Succeeded
            {
                return Err(StoreError::Conflict("result page authority mismatch".into()));
            }
            if run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr
                && run.config.retention.days != 0
                && run.created_at + ChronoDuration::days(i64::from(run.config.retention.days)) <= now
            {
                return Err(StoreError::RetentionDenied(
                    "committed page source expired".into(),
                ));
            }
        }
        let retained = run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr;
        let dataset = crate::dataset::prepare_memory(
            &g.dataset,
            run,
            commit.request_id,
            &commit.accepted,
            &commit.state_deltas,
            &commit.outbox,
            now,
        )?;
        let mut children = commit.children;
        if let Some(batch) = &children {
            if batch.run != commit.run
                || batch.parent_fence != Some((commit.request_id, commit.fence))
                || batch
                    .requests
                    .iter()
                    .any(|request| request.revisit_generation != 0)
            {
                return Err(StoreError::Conflict("result child authority mismatch".into()));
            }
        }
        if commit.status == FrontierStatus::Succeeded {
            if let Some(policy) = run
                .config
                .orchestration
                .as_ref()
                .and_then(|cfg| cfg.recrawl.as_ref())
            {
                let current = g
                    .requests
                    .envelopes
                    .get(&commit.request_id)
                    .map(|(envelope, _, _)| envelope.clone())
                    .or_else(|| {
                        g.frontier
                            .iter()
                            .find(|row| row.e.id == commit.request_id)
                            .map(|row| {
                                RequestEnvelopeV1::get(row.e.url.clone(), row.e.depth, row.e.discovered_from)
                            })
                    })
                    .ok_or_else(|| nf("frontier row", commit.request_id))?;
                let deadline = run.started_at.unwrap_or(run.created_at)
                    + ChronoDuration::seconds(i64::from(run.config.limits.duration_seconds));
                if let Some(next) = policy.next_visit(&current, commit.request_id, now, deadline)? {
                    let principal = g
                        .requests
                        .principals
                        .get(&commit.request_id)
                        .cloned()
                        .unwrap_or_else(|| "anonymous".into());
                    let batch = children.get_or_insert_with(|| {
                        let mut batch = RequestBatchV1::new(
                            run.tenant,
                            run.id,
                            principal,
                            Digest::of("crawlx/recrawl-batch/v1", &commit.request_id.to_be_bytes()),
                            Vec::new(),
                        );
                        batch.parent_fence = Some((commit.request_id, commit.fence));
                        batch
                    });
                    batch.requests.push(next);
                }
            }
        }
        if let Some(batch) = &children {
            append(&mut g, batch, now, true)?;
        }
        crate::dataset::apply_prepared(&mut g.dataset, dataset);
        if let Some(page) = commit.page {
            // The latest projection and history own independent lifetimes. Clone once here,
            // never in producers or while moving the result through the commit contract.
            match g
                .pages
                .iter_mut()
                .find(|p| p.run == page.run && p.url.key == page.url.key)
            {
                Some(latest) => latest.clone_from(&page),
                None => g.pages.push(page.clone()),
            }
            if retained {
                g.page_captures.insert((page.run, page.frontier_id), page);
            }
        }
        if let Some((_, _, state_version)) = g.requests.envelopes.get_mut(&commit.request_id) {
            *state_version = version.saturating_add(1);
        }
        let row = &mut g.frontier[parent_index];
        row.e.status = commit.status;
        row.e.denial_reason = commit.reason;
        row.owner = None;
        row.expires = None;
        Ok(())
    }
}
