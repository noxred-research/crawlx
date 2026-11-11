//! Memory frontier transaction helpers; same bounds and fence semantics as PostgreSQL.
use super::*;
use crawlx_core::acquisition::{AcquisitionAllowanceV1, AcquisitionUsageV1};
use crawlx_core::orchestration::*;
use crawlx_core::request::{RequestEnvelopeV1, RequestIdentityV1};
use std::collections::BTreeSet;

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
    head_receipts: BTreeMap<(CrawlRunId, i64), HeadReceipt>,
    pub(super) observed_pages: BTreeMap<(CrawlRunId, i64), HeadEventCustody>,
    content_registry: crate::digest_registry::RegistryState,
}

impl RequestState {
    pub(super) fn purge_head_receipts(&mut self, run: CrawlRunId) {
        self.head_receipts.retain(|(owner, _), _| *owner != run);
        self.observed_pages.retain(|(owner, _), _| *owner != run);
        self.content_registry.purge_run(run);
    }
}

#[derive(Clone)]
enum HeadReceipt {
    Retained(Digest),
    Volatile(HeadEventCustody),
}

/// The writer owns the purge barrier until publication or physical rollback.
/// Dropping the caller closes `decision`, so cancellation cannot strand a late write.
struct HeadStaging {
    decision: tokio::sync::oneshot::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), StoreError>>,
}

impl HeadStaging {
    async fn start(
        guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        buffer: Arc<crate::DeliveryBuffer>,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        bytes: Vec<u8>,
    ) -> Result<(HeadEventCustody, Self), StoreError> {
        Self::start_named(guard, buffer, tenant, run, page, bytes, "_head_response").await
    }

    async fn start_named(
        guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        buffer: Arc<crate::DeliveryBuffer>,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        bytes: Vec<u8>,
        field: &'static str,
    ) -> Result<(HeadEventCustody, Self), StoreError> {
        let (ready, receive) = tokio::sync::oneshot::channel();
        let (decision, publication) = tokio::sync::oneshot::channel();
        // One owned write permit bounds staging tasks and makes purge await the
        // real backend writer, including spawn_blocking work after caller cancellation.
        let task = tokio::spawn(async move {
            let _guard = guard;
            let staged = async {
                let artifact = buffer
                    .insert(tenant, run, page, field, "application/json", &bytes)
                    .await?;
                let expires_at = buffer
                    .content_deadline(tenant, run, page, artifact.id)
                    .await?
                    .ok_or_else(head_unavailable)?;
                Ok::<_, StoreError>(HeadEventCustody {
                    tenant,
                    page,
                    artifact: artifact.id,
                    expires_at,
                })
            }
            .await;
            drop(bytes);
            match staged {
                Ok(custody) => {
                    let published = ready.send(Ok(custody)).is_ok() && publication.await.unwrap_or(false);
                    if !published {
                        buffer.ack(tenant, run, page).await?;
                    }
                }
                Err(error) => {
                    let error = buffer.ack(tenant, run, page).await.err().unwrap_or(error);
                    let _closed = ready.send(Err(error));
                }
            }
            Ok(())
        });
        let staged = receive
            .await
            .unwrap_or_else(|_| Err(StoreError::Backend("HEAD staging task stopped".into())));
        match staged {
            Ok(custody) => Ok((custody, Self { decision, task })),
            Err(error) => {
                task.await
                    .map_err(|error| StoreError::Backend(error.to_string()))??;
                Err(error)
            }
        }
    }

    async fn finish(self, published: bool) -> Result<(), StoreError> {
        let _closed = self.decision.send(published);
        self.task
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?
    }
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
    observed_timing: Option<(Timestamp, Timestamp)>,
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
    let (admitted_at, deadline) = observed_timing.unwrap_or_else(|| {
        (
            now,
            run.started_at.unwrap_or(run.created_at)
                + ChronoDuration::seconds(i64::from(run.config.limits.duration_seconds)),
        )
    });
    if !matches!(
        run.status,
        RunStatus::Queued | RunStatus::Running | RunStatus::Paused
    ) || admitted_at >= deadline
        || admitted_at > now
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
    if batch.producer_epoch != epoch || (sealed && batch.parent_fence.is_none() && observed_timing.is_none())
    {
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
        if observed_timing.is_none() && envelope.metadata.contains_key("observed_epoch") {
            return Err(StoreError::AccessDenied(
                "observation requires session transaction".into(),
            ));
        }
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
            observed: observed_timing.is_some(),
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
        append(&mut self.inner.lock(), &batch, self.clock.now(), false, None)
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
    pub(super) async fn request_methods_bulk(
        &self,
        run: CrawlRunId,
        ids: &[i64],
    ) -> Result<BTreeMap<i64, String>, StoreError> {
        if ids.len() > 1000 {
            return Err(StoreError::Conflict("invalid request method batch limit".into()));
        }
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let g = self.inner.lock();
        let owner = g.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != owner.tenant) {
            return Err(StoreError::AccessDenied("request method tenant mismatch".into()));
        }
        let expected: BTreeSet<i64> = ids.iter().copied().collect();
        let mut methods = BTreeMap::new();
        for row in g
            .frontier
            .iter()
            .filter(|row| row.e.run == run && expected.contains(&row.e.id))
        {
            let method = g
                .requests
                .envelopes
                .get(&row.e.id)
                .map_or("GET", |(envelope, _, _)| envelope.method.as_str());
            methods.insert(row.e.id, method.to_owned());
        }
        if let Some(id) = expected.iter().find(|id| !methods.contains_key(*id)) {
            return Err(nf("frontier row", id));
        }
        Ok(methods)
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
        let url_work = g
            .runs
            .get(&run)
            .is_none_or(|run| run.config.mode != crawlx_core::CrawlMode::Dynamic);
        let mut pending = false;
        let mut leased = false;
        for row in g
            .frontier
            .iter()
            .filter(|row| url_work && row.e.run == run && !row.observed)
        {
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

fn observed_session(
    g: &Inner,
    lease: &crawlx_core::custody::CustodyLease,
    now: Timestamp,
) -> Result<String, StoreError> {
    use crawlx_core::custody::CustodySource;
    lease.check_local_cancellation()?;
    let CustodySource::Session(id) = lease.source else {
        return Err(StoreError::LeaseLost);
    };
    let run = g.runs.get(&lease.run).ok_or(StoreError::LeaseLost)?;
    let session = g.sessions.get(&id).ok_or(StoreError::LeaseLost)?;
    if run.tenant != lease.tenant
        || crate::tenant::current().is_some_and(|tenant| tenant != lease.tenant)
        || run.status.is_terminal()
        || g.pending_purges.contains_key(&lease.run)
        || crate::codec::expiry(run.created_at, u32::from(run.config.retention.days))
            .is_some_and(|deadline| deadline <= now)
        || session.s.run != lease.run
        || session.owner != Some(lease.worker)
        || session.token != Some(lease.fence)
        || session.expires.is_none_or(|expires| expires <= now)
        || !matches!(
            session.s.status,
            SessionStatus::Running | SessionStatus::Recovering
        )
    {
        return Err(StoreError::LeaseLost);
    }
    Ok(session.s.role.0.clone())
}

fn check_observed_commit(
    g: &Inner,
    commit: &RequestCommitV1,
    now: Timestamp,
) -> Result<Option<String>, StoreError> {
    let Some(stored) = g.requests.envelopes.get(&commit.request_id) else {
        return if commit.observation.is_some() {
            Err(StoreError::LeaseLost)
        } else {
            Ok(None)
        };
    };
    let marker = stored.0.metadata.get("observed_epoch");
    let Some((lease, epoch)) = &commit.observation else {
        return if marker.is_some() {
            Err(StoreError::LeaseLost)
        } else {
            Ok(None)
        };
    };
    let principal = observed_session(g, lease, now)?;
    let proposal = ObservedRequestV1::from_staged(lease.clone(), *epoch, stored.0.clone())?;
    let batch = proposal.batch_id(&principal)?;
    if lease.run != commit.run
        || g.requests.principals.get(&commit.request_id) != Some(&principal)
        || marker != Some(&serde_json::to_value(batch)?)
        || !g
            .requests
            .receipts
            .get(&(commit.run, batch))
            .is_some_and(|(_, receipt)| receipt.inserted == [commit.request_id])
        || !g
            .frontier
            .iter()
            .any(|row| row.e.id == commit.request_id && row.observed && row.owner == Some(lease.worker))
        || commit.head_response.is_some()
    {
        return Err(StoreError::LeaseLost);
    }
    Ok(Some(principal))
}

impl MemoryStore {
    async fn append_observation(
        &self,
        mut request: ObservedRequestV1,
    ) -> Result<ObservedAppendV1, StoreError> {
        let run = <Self as RunRepo>::get(self, request.lease.run).await?;
        let (deadline, _) = crate::session_binding::budget_clock_deadline(self, &run, None).await?;
        let now = self.clock.now();
        let mut g = self.inner.lock();
        let principal = observed_session(&g, &request.lease, now)?;
        if request.acquired_at < run.started_at.unwrap_or(run.created_at)
            || request.acquired_at >= deadline
            || request.acquired_at > now
        {
            return Err(StoreError::AccessDenied(
                "observation acquired outside exploration deadline".into(),
            ));
        }
        let (batch_id, key) = request.prepare(&principal)?;
        if let Some((_, receipt)) = g.requests.receipts.get(&(request.lease.run, batch_id)) {
            let request_id = *receipt.inserted.first().ok_or(StoreError::LeaseLost)?;
            let generation = g
                .requests
                .envelopes
                .get(&request_id)
                .ok_or(StoreError::LeaseLost)?
                .1
                .revisit_generation;
            return Ok(ObservedAppendV1::Duplicate {
                request_id,
                revisit_generation: generation,
            });
        }
        let cap = g
            .runs
            .get(&request.lease.run)
            .ok_or(StoreError::LeaseLost)?
            .config
            .dynamic
            .max_page_revisits;
        let latest = g
            .requests
            .identities
            .range((request.lease.run, key, 0)..=(request.lease.run, key, u32::MAX))
            .next_back()
            .map(|((_, _, generation), _)| *generation);
        let generation = match latest {
            Some(generation) if generation >= u32::from(cap.min(128)) => {
                return Ok(ObservedAppendV1::CapReached)
            }
            Some(generation) => generation
                .checked_add(1)
                .ok_or_else(|| StoreError::Conflict("revisit generation overflow".into()))?,
            None => 0,
        };
        request.envelope.revisit_generation = generation;
        let mut batch = RequestBatchV1::new(
            request.lease.tenant,
            request.lease.run,
            principal,
            batch_id,
            vec![request.envelope],
        );
        batch.producer_epoch = g
            .requests
            .producers
            .get(&batch.run)
            .map_or(1, |(epoch, _)| *epoch);
        let receipt = append(&mut g, &batch, now, true, Some((request.acquired_at, deadline)))?;
        let request_id = *receipt.inserted.first().ok_or(StoreError::LeaseLost)?;
        Ok(ObservedAppendV1::Appended {
            request_id,
            revisit_generation: generation,
        })
    }
}

#[async_trait]
impl RequestCommitRepo for MemoryStore {
    async fn append_observed_fenced(
        &self,
        request: ObservedRequestV1,
    ) -> Result<ObservedAppendV1, StoreError> {
        self.append_observation(request).await
    }
    async fn lease_observed_fenced(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
        epoch: crawlx_core::ObservationEpoch,
        request_id: i64,
    ) -> Result<Option<(FrontierEntry, i64)>, StoreError> {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        let principal = observed_session(&g, lease, now)?;
        let stored = g
            .requests
            .envelopes
            .get(&request_id)
            .ok_or(StoreError::LeaseLost)?;
        let proposal = ObservedRequestV1::from_staged(lease.clone(), epoch, stored.0.clone())?;
        let batch = proposal.batch_id(&principal)?;
        if g.requests.principals.get(&request_id) != Some(&principal)
            || stored.0.metadata.get("observed_epoch") != Some(&serde_json::to_value(batch)?)
            || !g
                .requests
                .receipts
                .get(&(lease.run, batch))
                .is_some_and(|(_, receipt)| receipt.inserted == [request_id])
        {
            return Err(StoreError::LeaseLost);
        }
        let Some(index) = g.frontier.iter().position(|row| {
            row.e.id == request_id
                && row.e.run == lease.run
                && row.observed
                && row.e.status == FrontierStatus::Pending
                && row.next_attempt_at <= now
                && row.e.attempts < u16::MAX
        }) else {
            return Ok(None);
        };
        let token = g
            .fence
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("lease fence overflow".into()))?;
        g.fence = token;
        let row = &mut g.frontier[index];
        row.e.status = FrontierStatus::Leased;
        row.e.attempts += 1;
        row.owner = Some(lease.worker);
        row.token = Some(token);
        row.expires = Some(now + chrono_dur(self.url_ttl));
        Ok(Some((row.e.clone(), token)))
    }
    async fn commit_observed_fenced(
        &self,
        mut commit: RequestCommitV1,
        lease: crawlx_core::custody::CustodyLease,
        epoch: crawlx_core::ObservationEpoch,
    ) -> Result<ObservedCommitV1, StoreError> {
        commit.observation = Some((lease, epoch));
        self.commit_fenced(commit).await?;
        Ok(ObservedCommitV1::Committed)
    }
    async fn begin_feed_finalization(
        &self,
        run: CrawlRunId,
        reason: Option<TerminalReason>,
    ) -> Result<Option<TerminalReason>, StoreError> {
        self.begin_feed_finalization_owned(run, reason).await
    }
    async fn stage_feed_batches(
        &self,
        run: CrawlRunId,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.stage_feed_batches_owned(run, batches).await
    }
    async fn staged_feed_batch(
        &self,
        run: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<crawlx_core::dataset::DeliveryBatchV1>, StoreError> {
        self.staged_feed_batch_owned(run, feed, idempotency_key).await
    }
    async fn finalize_run_feeds(
        &self,
        run: CrawlRunId,
        status: RunStatus,
        reason: TerminalReason,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.finalize_run_feeds_owned(run, status, reason, batches).await
    }
    async fn commit_fenced(&self, mut commit: RequestCommitV1) -> Result<(), StoreError> {
        // Serialize hash arbitration across staging I/O without holding the state lock over await.
        let _digest_gate = if commit.content_dedupe.is_some() {
            let gate = Arc::clone(&self.inner.lock().requests.content_registry.gate);
            Some(gate.lock_owned().await)
        } else {
            None
        };
        if commit.content_dedupe.is_some() {
            let g = self.inner.lock();
            let run = g.runs.get(&commit.run).ok_or(StoreError::LeaseLost)?;
            crate::digest_registry::check_source(run, self.clock.now())?;
            crate::digest_registry::validate_commit(&commit, run.tenant)?;
            let claim = commit.content_dedupe.as_ref().ok_or(StoreError::LeaseLost)?;
            let outcome = g
                .requests
                .content_registry
                .prepare(claim, commit.request_id, self.clock.now());
            // Duplicate evidence is final already. Canonical storage time is assigned only in
            // the publication lock below; volatile readers obtain it from the hash-only receipt.
            if outcome.is_duplicate() {
                crate::digest_registry::apply_outcome(&mut commit, &outcome);
            }
        }
        self.validate_dataset_results(commit.run, &commit.accepted, &commit.state_deltas, &commit.outbox)
            .await?;
        let head_receipt = commit.head_response_receipt()?;
        let observed_page = if commit.observation.is_some() && commit.page.is_some() {
            let mut g = self.inner.lock();
            check_observed_commit(&g, &commit, self.clock.now())?;
            let run = g.runs.get(&commit.run).ok_or(StoreError::LeaseLost)?;
            if run.config.retention.mode == RetentionMode::Zdr {
                if !live_parent(&g, commit.run, commit.request_id, commit.fence, self.clock.now()) {
                    return Err(StoreError::LeaseLost);
                }
                let buffer = self.dataset_delivery.lock().clone().ok_or_else(|| {
                    StoreError::RetentionDenied("observed page requires volatile storage".into())
                })?;
                let tenant = run.tenant;
                if g.head_deliveries
                    .get(&commit.run)
                    .is_some_and(|prior| !Arc::ptr_eq(prior, &buffer))
                {
                    return Err(head_unavailable());
                }
                g.head_deliveries
                    .entry(commit.run)
                    .or_insert_with(|| Arc::clone(&buffer));
                Some((
                    buffer,
                    tenant,
                    serde_json::to_vec(commit.page.as_ref().ok_or(StoreError::LeaseLost)?)?,
                ))
            } else {
                None
            }
        } else {
            None
        };
        let (observed_custody, observed_staging) = if let Some((buffer, tenant, bytes)) = observed_page {
            let (custody, staging) = HeadStaging::start_named(
                Arc::clone(&self.head_custody).write_owned().await,
                buffer,
                tenant,
                commit.run,
                commit.request_id,
                bytes,
                "page_record",
            )
            .await?;
            (Some(custody), Some(staging))
        } else {
            (None, None)
        };
        // Serialize HEAD publication and replay so duplicate commits cannot stage
        // a second receipt or renew custody while the first commit awaits I/O.
        let mut custody_guard = if head_receipt.is_some() {
            Some(Arc::clone(&self.head_custody).write_owned().await)
        } else {
            None
        };
        if let Some(receipt) = head_receipt {
            self.check_head_authority(commit.run).await?;
            let stored = {
                let g = self.inner.lock();
                if g.pending_purges.contains_key(&commit.run) {
                    return Err(head_unavailable());
                }
                let run = g
                    .runs
                    .get(&commit.run)
                    .ok_or_else(|| nf("crawl run", commit.run))?;
                if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant)
                    || run.terminal_reason == Some(TerminalReason::AuthorizationRevoked)
                {
                    return Err(StoreError::AccessDenied("HEAD response authority revoked".into()));
                }
                let tenant = <TenantId as serde::Deserialize>::deserialize(
                    &commit.head_response.as_ref().ok_or(StoreError::LeaseLost)?["acquisition"]["tenant"],
                )?;
                if tenant != run.tenant {
                    return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
                }
                g.requests
                    .head_receipts
                    .get(&(commit.run, commit.request_id))
                    .cloned()
            };
            if let Some(stored) = stored {
                let stored = match stored {
                    HeadReceipt::Retained(digest) => digest,
                    HeadReceipt::Volatile(custody) => {
                        self.read_head_custody(commit.run, &custody).await?.receipt
                    }
                };
                return if stored == receipt {
                    Ok(())
                } else {
                    Err(StoreError::Conflict("HEAD response receipt changed".into()))
                };
            }
        }
        let volatile_head = head_receipt.is_some()
            && self
                .inner
                .lock()
                .runs
                .get(&commit.run)
                .is_some_and(|run| run.config.retention.mode == RetentionMode::Zdr);
        let head_bytes = if volatile_head {
            commit
                .head_response
                .as_ref()
                .zip(head_receipt)
                .map(|(observation, receipt)| {
                    serde_json::to_vec(&HeadVolatilePayload { receipt, observation })
                })
                .transpose()?
        } else {
            None
        };
        let custody = if head_receipt.is_some() {
            let mut g = self.inner.lock();
            if g.pending_purges.contains_key(&commit.run) {
                return Err(head_unavailable());
            }
            let run = g
                .runs
                .get(&commit.run)
                .ok_or_else(|| nf("crawl run", commit.run))?;
            let tenant = run.tenant;
            let acquisition_tenant = <TenantId as serde::Deserialize>::deserialize(
                &commit.head_response.as_ref().ok_or(StoreError::LeaseLost)?["acquisition"]["tenant"],
            )?;
            if acquisition_tenant != tenant
                || crate::tenant::current().is_some_and(|current| current != tenant)
            {
                return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
            }
            if run.status.is_terminal() {
                return Err(StoreError::AccessDenied("HEAD response run is terminal".into()));
            }
            if !live_parent(&g, commit.run, commit.request_id, commit.fence, self.clock.now()) {
                return Err(StoreError::LeaseLost);
            }
            let (queued, identity, version) = g
                .requests
                .envelopes
                .get(&commit.request_id)
                .ok_or(StoreError::LeaseLost)?;
            if queued.method != "HEAD" {
                return Err(StoreError::Conflict(
                    "HEAD response queued method mismatch".into(),
                ));
            }
            let acquisition = &commit.head_response.as_ref().ok_or(StoreError::LeaseLost)?["acquisition"];
            // URL evidence may redact path/query secrets; exact authority comes from the queue key.
            let requested_url = <url::Url as serde::Deserialize>::deserialize(&acquisition["requestedUrl"])?;
            if !matches!(requested_url.scheme(), "http" | "https")
                || requested_url.origin() != queued.url.url.origin()
                || <Digest as serde::Deserialize>::deserialize(&acquisition["requestDigest"])? != identity.key
            {
                return Err(StoreError::Conflict(
                    "HEAD response request identity mismatch".into(),
                ));
            }
            if *version != commit.expected_state_version {
                return Err(StoreError::Conflict("request state version changed".into()));
            }
            if run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr {
                let buffer = self.dataset_delivery.lock().clone().ok_or_else(|| {
                    StoreError::RetentionDenied("HEAD response requires volatile storage".into())
                })?;
                let limits = buffer.limits();
                if !buffer.is_enabled()
                    || head_bytes
                        .as_ref()
                        .is_none_or(|bytes| bytes.len() > limits.max_bytes)
                    || limits.max_entries == 0
                {
                    return Err(StoreError::RetentionDenied(
                        "HEAD response exceeds volatile capacity".into(),
                    ));
                }
                if g.head_deliveries
                    .get(&commit.run)
                    .is_some_and(|prior| !Arc::ptr_eq(prior, &buffer))
                {
                    return Err(head_unavailable());
                }
                // Pin only after deterministic admission. Once I/O starts, retain its
                // owner even on cancellation or unknown failure so purge can erase orphans.
                g.head_deliveries
                    .entry(commit.run)
                    .or_insert_with(|| Arc::clone(&buffer));
                g.next_dataset_action = g
                    .next_dataset_action
                    .checked_add(1)
                    .ok_or_else(|| StoreError::RetentionDenied("HEAD response namespace exhausted".into()))?;
                Some((
                    buffer,
                    tenant,
                    crate::dataset::action_page(g.next_dataset_action)?,
                ))
            } else {
                None
            }
        } else {
            None
        };
        // Stage in existing scoped custody, never in the event vector. Publication below
        // rechecks the fence and all transaction conditions without holding a lock over await.
        let (staged, staging) = if let Some((buffer, tenant, page)) = &custody {
            let (staged, staging) = HeadStaging::start(
                custody_guard.take().ok_or_else(head_unavailable)?,
                Arc::clone(buffer),
                *tenant,
                commit.run,
                *page,
                head_bytes.ok_or_else(head_unavailable)?,
            )
            .await?;
            (Some(staged), Some(staging))
        } else {
            (None, None)
        };
        if head_receipt.is_some() {
            if let Err(error) = self.check_head_authority(commit.run).await {
                if let Some(staging) = staging {
                    staging.finish(false).await?;
                }
                return Err(error);
            }
        }
        let mut published = false;
        let result = (|| {
            let now = self.clock.now();
            let mut g = self.inner.lock();
            if g.pending_purges.contains_key(&commit.run) {
                return Err(head_unavailable());
            }
            let run = g
                .runs
                .get(&commit.run)
                .ok_or_else(|| nf("crawl run", commit.run))?;
            if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
                return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
            }
            if head_receipt.is_some() && run.status.is_terminal() {
                return Err(StoreError::AccessDenied("HEAD response run is terminal".into()));
            }
            if !live_parent(&g, commit.run, commit.request_id, commit.fence, now) {
                return Err(StoreError::LeaseLost);
            }
            let observed_principal = check_observed_commit(&g, &commit, now)?;
            if head_receipt.is_some() {
                let queued = &g
                    .requests
                    .envelopes
                    .get(&commit.request_id)
                    .ok_or(StoreError::LeaseLost)?
                    .0;
                if queued.method != "HEAD" {
                    return Err(StoreError::Conflict(
                        "HEAD response queued method mismatch".into(),
                    ));
                }
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
            if observed_custody
                .as_ref()
                .is_some_and(|custody| custody.expires_at <= now)
            {
                return Err(head_unavailable());
            }
            if head_receipt.is_some()
                && run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr
                && run.config.retention.days != 0
                && run.created_at + ChronoDuration::days(i64::from(run.config.retention.days)) <= now
            {
                return Err(StoreError::RetentionDenied(
                    "committed HEAD source expired".into(),
                ));
            }
            if staged.as_ref().is_some_and(|custody| custody.expires_at <= now) {
                return Err(head_unavailable());
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
            crate::digest_registry::validate_commit(&commit, run.tenant)?;
            let digest_outcome = commit
                .content_dedupe
                .as_ref()
                .map(|claim| g.requests.content_registry.prepare(claim, commit.request_id, now));
            if let Some(outcome) = &digest_outcome {
                crate::digest_registry::apply_outcome(&mut commit, outcome);
            }
            let dataset = crate::dataset::prepare_memory(
                &g.dataset,
                run,
                commit.request_id,
                &commit.accepted,
                &commit.state_deltas,
                &commit.outbox,
                now,
            )?;
            let mut children = commit.children.take();
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
            if commit.status == FrontierStatus::Succeeded && observed_principal.is_none() {
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
                                    RequestEnvelopeV1::get(
                                        row.e.url.clone(),
                                        row.e.depth,
                                        row.e.discovered_from,
                                    )
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
                append(&mut g, batch, now, true, None)?;
            }
            if let Some((claim, outcome)) = commit.content_dedupe.as_ref().zip(digest_outcome.as_ref()) {
                g.requests
                    .content_registry
                    .apply(claim, commit.request_id, outcome.clone());
            }
            crate::dataset::apply_prepared(&mut g.dataset, dataset);
            if let Some(page) = commit.page {
                // The latest projection and history own independent lifetimes. Clone once here,
                // never in producers or while moving the result through the commit contract.
                if observed_custody.is_none()
                    && !digest_outcome
                        .as_ref()
                        .is_some_and(|outcome| outcome.is_duplicate())
                {
                    let same_role = g.pages.iter().position(|prior| {
                        prior.run == page.run
                            && prior.url.key == page.url.key
                            && observed_principal.as_ref().is_none_or(|role| {
                                g.requests
                                    .principals
                                    .get(&prior.frontier_id)
                                    .map_or("anonymous", String::as_str)
                                    == role
                            })
                    });
                    match same_role {
                        Some(index) if observed_principal.is_none() => g.pages[index].clone_from(&page),
                        Some(_) => {}
                        None => g.pages.push(page.clone()),
                    }
                }
                if let Some(custody) = &observed_custody {
                    g.requests
                        .observed_pages
                        .insert((page.run, page.frontier_id), custody.clone());
                }
                if retained {
                    g.page_captures.insert((page.run, page.frontier_id), page);
                }
            }
            if let Some(payload) = commit.head_response {
                push_event(
                    &mut g,
                    commit.run,
                    "head_response",
                    staged
                        .as_ref()
                        .map_or(payload, |custody| serde_json::json!({"headCustody": custody})),
                    now,
                );
                published = true;
            }
            if let Some(receipt) = head_receipt {
                g.requests.head_receipts.insert(
                    (commit.run, commit.request_id),
                    staged.map_or(HeadReceipt::Retained(receipt), HeadReceipt::Volatile),
                );
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
        })();
        if let Some(staging) = staging {
            staging.finish(published).await?;
        }
        if let Some(staging) = observed_staging {
            staging.finish(result.is_ok()).await?;
        }
        result
    }
}

#[async_trait]
impl crawlx_core::digest_registry::DigestRegistryRepo for MemoryStore {
    async fn digest_outcome(
        &self,
        run: CrawlRunId,
        frontier_id: i64,
    ) -> Result<Option<crawlx_core::digest_registry::DigestOutcomeV1>, StoreError> {
        let g = self.inner.lock();
        if g.pending_purges.contains_key(&run) {
            return Err(head_unavailable());
        }
        let source = g.runs.get(&run).ok_or_else(|| nf("crawl run", run))?;
        crate::digest_registry::check_source(source, self.clock.now())?;
        Ok(g.requests.content_registry.outcome(run, frontier_id))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    #[tokio::test]
    async fn cancelled_filesystem_staging_keeps_purge_barrier_until_writer_rollback() {
        let root = tempfile::tempdir().unwrap();
        let now = Timestamp::from_timestamp(1_700_000_000, 0).unwrap();
        let clock = Arc::new(crawlx_core::time::ManualClock::new(now));
        let buffer = Arc::new(
            crate::DeliveryBuffer::open_fs(root.path(), clock.clone(), crate::BufferLimits::default())
                .await
                .unwrap(),
        );
        let store = Arc::new(MemoryStore::with_clock(clock));
        let tenant = TenantId::new();
        let run = crate::testkit::crawl_run(
            tenant,
            crate::testkit::create_crawl("https://example.test/", &[], 1),
        );
        let run_id = run.id;
        {
            let mut g = store.inner.lock();
            g.runs.insert(run_id, run);
            g.head_deliveries.insert(run_id, Arc::clone(&buffer));
        }
        // Hold the real filesystem writer behind its OS lock, not a mocked future.
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.path().join("zdr/.lock"))
            .unwrap();
        lock.lock().unwrap();
        let guard = Arc::clone(&store.head_custody).write_owned().await;
        let mut staging = Box::pin(HeadStaging::start(
            guard,
            Arc::clone(&buffer),
            tenant,
            run_id,
            -7,
            br#"{"receipt":"test","observation":{}}"#.to_vec(),
        ));
        // Poll through task submission before cancelling the owning commit future.
        poll_fn(|cx| {
            assert!(staging.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::task::yield_now().await;
        drop(staging);
        assert!(store.head_custody.try_write().is_err());
        let purging = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.purge_run(run_id).await })
        };
        tokio::task::yield_now().await;
        assert!(store.inner.lock().pending_purges.contains_key(&run_id));
        assert!(!purging.is_finished());
        lock.unlock().unwrap();
        purging.await.unwrap().unwrap();
        assert!(!store.inner.lock().runs.contains_key(&run_id));
        assert!(buffer.get(tenant, run_id, -7).await.unwrap().is_none());
        assert!(buffer.is_empty().await.unwrap());
    }
}
