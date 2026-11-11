//! Bounded report producers with explicit cancellation and owned draining.
//!
//! Run [`ReportDrain::run`] inside the caller's structured task set or join it
//! directly. This module never spawns detached work. Graceful drain cancellation
//! closes admission, persists accepted facts, and flushes counted diagnostic loss
//! under the same still-live custody lease. Hard lease cancellation always wins.

use crawlx_core::acquisition::AcquisitionResultV1;
use crawlx_core::custody::CustodyLease;
use crawlx_core::hash::Digest;
use crawlx_core::report_history::{
    ProcessorIdentityV1, ProcessorStageV1, ReportDataV1, ReportFactV1, ReportHistoryRepo, ReportKindV1,
    StageOutcomeV1,
};
use crawlx_core::{Clock, StoreError, Timestamp};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Maximum configured queue capacity, independent of repository page size.
pub const MAX_REPORT_QUEUE_CAPACITY: usize = 4096;

/// Explicit producer or drain failure; storage errors retain their source chain.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReportSinkError {
    /// Caller requested cancellation; no implicit successful shutdown.
    #[error("report operation cancelled")]
    Cancelled,
    /// Receiver no longer accepts facts.
    #[error("report sink closed")]
    Closed,
    /// Bounded diagnostics queue dropped this fact and counted it.
    #[error("report diagnostics queue full")]
    Full,
    /// Durable pipeline outcomes cannot use the lossy path.
    #[error("pipeline facts require lossless report submission")]
    PipelineMustBeLossless,
    /// Queue allocation was not bounded correctly.
    #[error("report queue capacity must be in 1..=4096")]
    InvalidCapacity,
    /// Loss count cannot fit the storage schema.
    #[error("report diagnostic loss counter overflow")]
    CounterOverflow,
    /// A producer panicked while coordinating queue closure.
    #[error("report queue coordination poisoned")]
    CoordinationPoisoned,
    /// Validation, ownership, retention or backend failure.
    #[error("report storage failed")]
    Store(#[from] StoreError),
}

#[derive(Debug, Default)]
struct Diagnostics {
    dropped: AtomicU64,
    // Serialize try_send + loss counting against receiver.close + final snapshot.
    // No guard crosses an await. This avoids losing a Full count during shutdown.
    admission: Mutex<()>,
}

/// Cloneable bounded producer. Pipeline outcomes must use [`Self::submit`].
#[derive(Clone, Debug)]
#[must_use]
pub struct ReportSink {
    sender: mpsc::Sender<ReportFactV1>,
    diagnostics: Arc<Diagnostics>,
}

/// Owned drain future; dropping it closes the queue, never detaches a task.
#[derive(Debug)]
#[must_use]
pub struct ReportDrain {
    receiver: mpsc::Receiver<ReportFactV1>,
    diagnostics: Arc<Diagnostics>,
}

impl ReportSink {
    /// Create a finite queue without spawning background tasks.
    ///
    /// # Errors
    /// Returns [`ReportSinkError::InvalidCapacity`] outside 1..=4096.
    pub fn bounded(capacity: usize) -> Result<(Self, ReportDrain), ReportSinkError> {
        if !(1..=MAX_REPORT_QUEUE_CAPACITY).contains(&capacity) {
            return Err(ReportSinkError::InvalidCapacity);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        let diagnostics = Arc::new(Diagnostics::default());
        Ok((
            Self {
                sender,
                diagnostics: Arc::clone(&diagnostics),
            },
            ReportDrain {
                receiver,
                diagnostics,
            },
        ))
    }

    /// Await bounded admission without dropping a pipeline outcome on pressure.
    ///
    /// Cancellation is checked while reserving capacity, before moving the fact.
    /// Success means enqueued, not committed; join the drain before fence commit.
    /// # Errors
    /// Returns cancellation, closed-channel or malformed-evidence errors.
    pub async fn submit(
        &self,
        fact: ReportFactV1,
        cancellation: &CancellationToken,
    ) -> Result<(), ReportSinkError> {
        fact.validate()?;
        let permit = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(ReportSinkError::Cancelled),
            permit = self.sender.reserve() => permit.map_err(|_| ReportSinkError::Closed)?,
        };
        permit.send(fact);
        Ok(())
    }

    /// Submit diagnostics without waiting; count only pressure-induced drops.
    ///
    /// Pipeline facts are refused without loss counting and require lossless
    /// submission. Closure and malformed input are explicit errors, not drops.
    /// # Errors
    /// Returns full, closed, invalid fact, coordination or counter errors.
    pub fn try_submit(&self, fact: ReportFactV1) -> Result<(), ReportSinkError> {
        fact.validate()?;
        if fact.data.kind() == ReportKindV1::Pipeline {
            return Err(ReportSinkError::PipelineMustBeLossless);
        }
        let _guard = self
            .diagnostics
            .admission
            .lock()
            .map_err(|_| ReportSinkError::CoordinationPoisoned)?;
        match self.sender.try_send(fact) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ReportSinkError::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.diagnostics
                    .dropped
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        count.checked_add(1).filter(|next| i64::try_from(*next).is_ok())
                    })
                    .map_err(|_| ReportSinkError::CounterOverflow)?;
                Err(ReportSinkError::Full)
            }
        }
    }

    /// Exact pressure-loss count so far; never includes rejected pipeline facts.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.diagnostics.dropped.load(Ordering::Relaxed)
    }
}

impl ReportDrain {
    /// Persist accepted facts sequentially, then flush diagnostic loss once.
    ///
    /// `shutdown` is graceful drain, distinct from hard cancellation captured in
    /// `lease`. Cancellation closes admission, drains accepted facts and writes
    /// Loss with `loss_id` and the injected clock, then returns `Cancelled`.
    /// Natural producer closure flushes and returns success. Callers must await
    /// this future before releasing or committing away the producer fence.
    /// # Errors
    /// Returns explicit cancellation after a successful graceful flush, or the
    /// first validation, lease or storage failure. Failed appends never become
    /// successful pipeline checkpoints; repository idempotency permits recovery.
    pub async fn run(
        mut self,
        repo: &dyn ReportHistoryRepo,
        lease: &CustodyLease,
        loss_id: Digest,
        clock: &dyn Clock,
        shutdown: &CancellationToken,
    ) -> Result<(), ReportSinkError> {
        let mut cancelled = false;
        loop {
            let fact = tokio::select! {
                biased;
                () = shutdown.cancelled(), if !cancelled => {
                    self.close()?;
                    cancelled = true;
                    continue;
                }
                () = lease.cancelled() => return Err(StoreError::LeaseLost.into()),
                fact = self.receiver.recv() => fact,
            };
            let Some(fact) = fact else { break };
            append_checked(repo, lease, &fact).await?;
        }
        self.close()?;
        let dropped = self.diagnostics.dropped.load(Ordering::Relaxed);
        if dropped != 0 {
            let fact = ReportFactV1::new(lease, loss_id, clock.now(), ReportDataV1::Loss { dropped });
            append_checked(repo, lease, &fact).await?;
        }
        if cancelled {
            Err(ReportSinkError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn close(&mut self) -> Result<(), ReportSinkError> {
        let _guard = self
            .diagnostics
            .admission
            .lock()
            .map_err(|_| ReportSinkError::CoordinationPoisoned)?;
        self.receiver.close();
        Ok(())
    }
}

/// Persist one fact directly before a producer's fenced commit.
///
/// This path is lossless and requires no background task. Cancellation is
/// checked before append. An in-flight durable append is awaited, not abandoned
/// with an unknown remote outcome; storage revalidates live authority itself.
/// # Errors
/// Returns explicit cancellation, invalid evidence, lease loss or backend error.
pub async fn record_report_fact(
    repo: &dyn ReportHistoryRepo,
    lease: &CustodyLease,
    fact: &ReportFactV1,
    cancellation: &CancellationToken,
) -> Result<u64, ReportSinkError> {
    if cancellation.is_cancelled() {
        return Err(ReportSinkError::Cancelled);
    }
    append_checked(repo, lease, fact).await.map_err(Into::into)
}

async fn append_checked(
    repo: &dyn ReportHistoryRepo,
    lease: &CustodyLease,
    fact: &ReportFactV1,
) -> Result<u64, StoreError> {
    fact.validate()?;
    fact.validate_lease(lease)?;
    repo.append_fact(lease, fact).await
}

/// Project only acquisition measurements, never decoded representation length.
///
/// Duration remains unknown without an observed elapsed scope. No fact is
/// produced when neither wire bytes nor duration were measured. Only opaque
/// request identity is retained; URLs and connection addresses are not copied.
/// # Errors
/// Returns lease loss for foreign scope or serialization errors for overflow.
pub fn acquisition_wire_fact(
    lease: &CustodyLease,
    id: Digest,
    at: Timestamp,
    result: &AcquisitionResultV1,
) -> Result<Option<ReportFactV1>, StoreError> {
    if result.tenant != lease.tenant || result.run != lease.run {
        return Err(StoreError::LeaseLost);
    }
    let duration_us = result
        .elapsed_scope
        .map(|_| {
            result
                .elapsed_ms
                .checked_mul(1000)
                .ok_or_else(|| StoreError::Serialization("acquisition duration overflow".into()))
        })
        .transpose()?;
    if result.wire_bytes.is_none() && duration_us.is_none() {
        return Ok(None);
    }
    let mut fact = ReportFactV1::new(
        lease,
        id,
        at,
        ReportDataV1::Wire {
            received_bytes: result.wire_bytes,
            sent_bytes: None,
            duration_us,
        },
    );
    fact.url_key = Some(result.request_digest);
    fact.attempt = u16::from(result.attempts.max(1));
    fact.validate()?;
    Ok(Some(fact))
}

/// Project a measured final DNS lookup from a response receipt, if present.
///
/// Captured batches supersede this final-response fallback because batches also
/// include failures and retries. Do not record both for one acquisition attempt.
/// # Errors
/// Returns foreign-scope, non-DNS payload or finite-schema validation errors.
pub fn acquisition_dns_fact(
    lease: &CustodyLease,
    id: Digest,
    at: Timestamp,
    result: &AcquisitionResultV1,
) -> Result<Option<ReportFactV1>, StoreError> {
    if result.tenant != lease.tenant || result.run != lease.run {
        return Err(StoreError::LeaseLost);
    }
    let Some(data) = &result.dns_report else {
        return Ok(None);
    };
    if data.kind() != ReportKindV1::Dns {
        return Err(StoreError::Serialization(
            "acquisition dns payload is not dns evidence".into(),
        ));
    }
    let id = Digest::of("crawlx:report:dns-final:v1", &id.0);
    let mut fact = ReportFactV1::new(lease, id, at, data.clone());
    fact.url_key = Some(result.request_digest);
    fact.attempt = u16::from(result.attempts.max(1));
    fact.validate()?;
    Ok(Some(fact))
}

/// Directly record final DNS and measured wire evidence before fence commit.
///
/// Returns the last committed sequence, or `None` if no measurement exists.
/// Use the batch helper instead of final DNS fallback when capture was enabled.
/// # Errors
/// Returns projection, cancellation, custody or repository failures.
pub async fn record_acquisition_report(
    repo: &dyn ReportHistoryRepo,
    lease: &CustodyLease,
    id: Digest,
    at: Timestamp,
    result: &AcquisitionResultV1,
    cancellation: &CancellationToken,
) -> Result<Option<u64>, ReportSinkError> {
    let dns = acquisition_dns_fact(lease, id, at, result)?;
    let wire = acquisition_wire_fact(lease, id, at, result)?;
    let mut sequence = None;
    for fact in [dns.as_ref(), wire.as_ref()].into_iter().flatten() {
        sequence = Some(record_report_fact(repo, lease, fact, cancellation).await?);
    }
    Ok(sequence)
}

/// Persist a bounded capture, including failed lookups and explicit batch loss.
///
/// IDs derive from the caller's stable attempt identity plus observation ordinal.
/// Call after the captured acquisition returns, even if its result is an error.
/// Captured DNS replaces the receipt's final-only DNS fallback, not wire facts.
/// # Errors
/// Returns malformed/oversized capture, overflow, cancellation or storage errors.
pub async fn record_dns_report_batch(
    repo: &dyn ReportHistoryRepo,
    lease: &CustodyLease,
    id: Digest,
    at: Timestamp,
    attempt: u16,
    batch: &crawlx_fetch::resolver::DnsReportBatchV1,
    cancellation: &CancellationToken,
) -> Result<Option<u64>, ReportSinkError> {
    if batch.observations.len() > crawlx_fetch::resolver::MAX_DNS_REPORTS || batch.loss_overflow {
        return Err(StoreError::Serialization("invalid bounded dns report capture".into()).into());
    }
    if attempt == 0
        || i64::try_from(batch.dropped).is_err()
        || batch
            .observations
            .iter()
            .any(|observation| observation.data.kind() != ReportKindV1::Dns)
    {
        return Err(StoreError::Serialization("invalid dns capture attempt, loss or payload".into()).into());
    }
    let mut sequence = None;
    let mut identity = [0_u8; 40];
    identity[..32].copy_from_slice(&id.0);
    for (index, observation) in batch.observations.iter().enumerate() {
        let ordinal = u64::try_from(index)
            .map_err(|_| StoreError::Serialization("dns observation ordinal overflow".into()))?;
        identity[32..].copy_from_slice(&ordinal.to_be_bytes());
        let fact_id = Digest::of("crawlx:report:dns-observation:v1", &identity);
        let mut fact = ReportFactV1::new(lease, fact_id, at, observation.data.clone());
        fact.host_key = Some(observation.host_key);
        fact.attempt = attempt;
        if let crawlx_core::custody::CustodySource::Url(request) = lease.source {
            fact.request_id = Some(request);
        }
        sequence = Some(record_report_fact(repo, lease, &fact, cancellation).await?);
    }
    if batch.dropped != 0 {
        let loss_id = Digest::of("crawlx:report:dns-loss:v1", &id.0);
        let mut fact = ReportFactV1::new(
            lease,
            loss_id,
            at,
            ReportDataV1::Loss {
                dropped: batch.dropped,
            },
        );
        fact.attempt = attempt;
        sequence = Some(record_report_fact(repo, lease, &fact, cancellation).await?);
    }
    Ok(sequence)
}

/// Monotonic per-attempt stage timer; wall time is supplied only when finishing.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct ReportStageTimer {
    started: Instant,
}

impl Default for ReportStageTimer {
    fn default() -> Self {
        Self::start()
    }
}

impl ReportStageTimer {
    /// Start a monotonic measurement.
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    /// Return elapsed microseconds with checked signed-storage conversion.
    ///
    /// # Errors
    /// Returns serialization error when elapsed duration cannot fit storage.
    pub fn elapsed_us(&self) -> Result<u64, StoreError> {
        let micros = u64::try_from(self.started.elapsed().as_micros())
            .map_err(|_| StoreError::Serialization("stage duration overflow".into()))?;
        i64::try_from(micros)
            .map_err(|_| StoreError::Serialization("stage duration exceeds storage range".into()))?;
        Ok(micros)
    }

    /// Finish a measured native stage with explicit processor revision.
    ///
    /// # Errors
    /// Returns serialization error for duration overflow.
    pub fn finish(
        &self,
        stage: ProcessorStageV1,
        outcome: StageOutcomeV1,
        processor: ProcessorIdentityV1,
        processor_version: u32,
    ) -> Result<ReportDataV1, StoreError> {
        Ok(ReportDataV1::Stage {
            stage,
            outcome,
            duration_us: self.elapsed_us()?,
            processor,
            processor_version,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use async_trait::async_trait;
    use crawlx_core::report_history::{
        PipelineStageV1, PipelineStateV1, ReportPageV1, ReportQueryV1, RouteCountersV1,
    };
    use crawlx_core::{CrawlRunId, TenantId, WorkerId};

    #[derive(Default)]
    struct MemoryRepo(Mutex<Vec<ReportFactV1>>);

    #[async_trait]
    impl ReportHistoryRepo for MemoryRepo {
        async fn append_fact(&self, lease: &CustodyLease, fact: &ReportFactV1) -> Result<u64, StoreError> {
            fact.validate_lease(lease)?;
            let mut facts = self.0.lock().unwrap();
            facts.push(fact.clone());
            Ok(u64::try_from(facts.len()).unwrap())
        }

        async fn query_facts(
            &self,
            _: TenantId,
            _: Option<CrawlRunId>,
            _: &ReportQueryV1,
        ) -> Result<ReportPageV1, StoreError> {
            Ok(ReportPageV1::default())
        }

        async fn route_counters(
            &self,
            _: TenantId,
            _: CrawlRunId,
        ) -> Result<Vec<RouteCountersV1>, StoreError> {
            Ok(Vec::new())
        }
    }

    fn lease() -> CustodyLease {
        CustodyLease::for_url(
            TenantId(uuid::Uuid::from_u128(1)),
            CrawlRunId(uuid::Uuid::from_u128(2)),
            1,
            WorkerId(uuid::Uuid::from_u128(3)),
            2,
        )
    }

    fn fact(lease: &CustodyLease, byte: u8) -> ReportFactV1 {
        ReportFactV1::new(lease, Digest([byte; 32]), at(), ReportDataV1::Loss { dropped: 1 })
    }

    fn at() -> Timestamp {
        Timestamp::from_timestamp(10, 0).unwrap()
    }

    #[tokio::test]
    async fn queue_pressure_flushes_exact_loss_under_same_lease() {
        let lease = lease();
        let repo = MemoryRepo::default();
        let (sink, drain) = ReportSink::bounded(1).unwrap();
        sink.try_submit(fact(&lease, 1)).unwrap();
        assert!(matches!(
            sink.try_submit(fact(&lease, 2)),
            Err(ReportSinkError::Full)
        ));
        assert!(matches!(
            sink.try_submit(fact(&lease, 3)),
            Err(ReportSinkError::Full)
        ));
        assert_eq!(sink.dropped(), 2);
        drop(sink);
        let clock = crawlx_core::time::ManualClock::new(at());
        drain
            .run(&repo, &lease, Digest([9; 32]), &clock, &CancellationToken::new())
            .await
            .unwrap();
        let facts = repo.0.lock().unwrap();
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[1].data, ReportDataV1::Loss { dropped: 2 });
        facts[1].validate_lease(&lease).unwrap();
    }

    #[tokio::test]
    async fn cancelled_lossless_submission_never_claims_success() {
        let lease = lease();
        let (sink, _drain) = ReportSink::bounded(1).unwrap();
        let cancellation = CancellationToken::new();
        sink.submit(fact(&lease, 1), &cancellation).await.unwrap();
        cancellation.cancel();
        assert!(matches!(
            sink.submit(fact(&lease, 2), &cancellation).await,
            Err(ReportSinkError::Cancelled)
        ));
        let pipeline = ReportFactV1::new(
            &lease,
            Digest([3; 32]),
            at(),
            ReportDataV1::Pipeline {
                stage: PipelineStageV1::Fetch,
                state: PipelineStateV1::Succeeded,
            },
        );
        assert!(matches!(
            sink.try_submit(pipeline),
            Err(ReportSinkError::PipelineMustBeLossless)
        ));
        assert_eq!(sink.dropped(), 0);
    }

    #[tokio::test]
    async fn shutdown_flushes_accepted_facts_but_reports_cancellation() {
        let lease = lease();
        let repo = MemoryRepo::default();
        let (sink, drain) = ReportSink::bounded(1).unwrap();
        sink.try_submit(fact(&lease, 1)).unwrap();
        assert!(matches!(
            sink.try_submit(fact(&lease, 2)),
            Err(ReportSinkError::Full)
        ));
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let clock = crawlx_core::time::ManualClock::new(at());
        assert!(matches!(
            drain.run(&repo, &lease, Digest([9; 32]), &clock, &shutdown).await,
            Err(ReportSinkError::Cancelled)
        ));
        assert_eq!(repo.0.lock().unwrap().len(), 2);
        assert!(matches!(
            sink.try_submit(fact(&lease, 3)),
            Err(ReportSinkError::Closed)
        ));
        assert_eq!(sink.dropped(), 1);
    }

    #[tokio::test]
    async fn direct_helper_refuses_cancelled_and_foreign_facts() {
        let lease = lease();
        let repo = MemoryRepo::default();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            record_report_fact(&repo, &lease, &fact(&lease, 1), &cancellation).await,
            Err(ReportSinkError::Cancelled)
        ));
        let mut foreign = fact(&lease, 2);
        foreign.tenant = TenantId(uuid::Uuid::from_u128(4));
        assert!(
            record_report_fact(&repo, &lease, &foreign, &CancellationToken::new())
                .await
                .is_err()
        );
        assert!(repo.0.lock().unwrap().is_empty());
    }

    #[test]
    fn acquisition_projection_keeps_unmeasured_wire_unknown() {
        let lease = lease();
        let mut result = AcquisitionResultV1::new(
            lease.run,
            lease.tenant,
            url::Url::parse("https://example.test/private?q=secret").unwrap(),
            Digest([4; 32]),
            crawlx_core::acquisition::BackendCapabilitiesV1::native_http("native", "1"),
        );
        result.decoded_bytes = 500;
        assert!(acquisition_wire_fact(&lease, Digest([1; 32]), at(), &result)
            .unwrap()
            .is_none());
        result.wire_bytes = Some(17);
        let measured = acquisition_wire_fact(&lease, Digest([1; 32]), at(), &result)
            .unwrap()
            .unwrap();
        assert_eq!(
            measured.data,
            ReportDataV1::Wire {
                received_bytes: Some(17),
                sent_bytes: None,
                duration_us: None
            }
        );
        let json = serde_json::to_string(&measured).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("example.test"));
    }

    #[tokio::test]
    async fn captured_dns_failure_persists_before_any_response() {
        use crawlx_core::report_history::DnsOutcomeV1;
        use crawlx_fetch::resolver::{capture_dns_reports, Resolver, StaticResolver};
        let lease = lease();
        let repo = MemoryRepo::default();
        let resolver = StaticResolver::new();
        let (result, batch) = capture_dns_reports(resolver.resolve_with_report("missing.test")).await;
        assert!(result.0.is_err());
        record_dns_report_batch(
            &repo,
            &lease,
            Digest([8; 32]),
            at(),
            2,
            &batch,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let facts = repo.0.lock().unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].attempt, 2);
        assert_eq!(facts[0].request_id, Some(1));
        assert!(facts[0].host_key.is_some());
        assert!(matches!(
            facts[0].data,
            ReportDataV1::Dns {
                outcome: DnsOutcomeV1::NotFound,
                recheck_at: None,
                ..
            }
        ));
        let json = serde_json::to_string(&facts[0]).unwrap();
        assert!(!json.contains("missing.test"));
    }

    #[tokio::test]
    async fn captured_dns_loss_is_explicit_and_bounded() {
        use crawlx_fetch::resolver::{capture_dns_reports, Resolver, StaticResolver};
        let lease = lease();
        let repo = MemoryRepo::default();
        let resolver = StaticResolver::new();
        let (_, batch) = capture_dns_reports(async {
            for _ in 0..66 {
                let _ = resolver.resolve_with_report("missing.test").await;
            }
        })
        .await;
        record_dns_report_batch(
            &repo,
            &lease,
            Digest([8; 32]),
            at(),
            1,
            &batch,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let facts = repo.0.lock().unwrap();
        assert_eq!(facts.len(), 65);
        assert_eq!(facts[64].data, ReportDataV1::Loss { dropped: 2 });
        assert_ne!(facts[0].id, facts[1].id);
        assert_ne!(facts[0].id, facts[64].id);
    }

    #[tokio::test(start_paused = true)]
    async fn stage_timer_uses_monotonic_elapsed_time() {
        let timer = ReportStageTimer::start();
        tokio::time::advance(std::time::Duration::from_micros(1234)).await;
        assert_eq!(timer.elapsed_us().unwrap(), 1234);
        assert_eq!(
            timer
                .finish(
                    ProcessorStageV1::Parse,
                    StageOutcomeV1::Cancelled,
                    ProcessorIdentityV1::Parser,
                    1,
                )
                .unwrap(),
            ReportDataV1::Stage {
                stage: ProcessorStageV1::Parse,
                outcome: StageOutcomeV1::Cancelled,
                duration_us: 1234,
                processor: ProcessorIdentityV1::Parser,
                processor_version: 1,
            }
        );
    }
}
