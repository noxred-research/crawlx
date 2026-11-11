//! Reviewed native lifecycle execution. No host callbacks, raw page handles or eval.
//!
//! Replacement requests are proposals only. Callers must reenter native admission
//! and append a new identity, never fetch a mutated already-leased request.

use crate::runtime::CpuPool;
use crawlx_core::{
    extensions::{
        document_item, json_size, ExtensionCallbackReceiptV1, ExtensionConfigV1, ExtensionError,
        ExtensionEventLimitsV1, ExtensionEventV1, ExtensionFailurePolicyV1, ExtensionPipelineV1,
        ExtensionReasonV1, ExtensionReceiptV1, ExtensionResultV1, ExtensionStageV1, ExtensionTerminalV1,
        HandlerV1, HeaderFactsV1, MAX_EXTENSION_BYTES,
    },
    extraction::{DocumentEnvelopeV1, QualityStatusV1},
    request::RequestEnvelopeV1,
};
use serde_json::Value;
use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Typed preparation result. This is not network or browser authority.
#[derive(Debug)]
#[non_exhaustive]
pub struct RequestPreparationV1 {
    /// Replacement proposal; append only after full native admission.
    pub replacement: Option<RequestEnvelopeV1>,
    /// Explicit label handler, distinct from learned URL route templates.
    pub route: HandlerV1,
}
/// One request's bounded lifecycle and shared acquisition-time header dispatcher.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RequestLifecycle {
    pipeline: Arc<ExtensionPipelineV1>,
    entered: Vec<String>,
    cleanup: Vec<String>,
    engine: Arc<Mutex<LifecycleEngine>>,
    _owner: Arc<LifecycleOwner>,
}
#[derive(Debug)]
struct LifecycleOwner {
    engine: Arc<Mutex<LifecycleEngine>>,
}

// Six reserved events and 48 KiB always remain available for failure and cleanup.
// Built-ins are finite, synchronous, non-reentrant operations; cleanup ignores
// cancellation but never invokes a host closure, network, browser or storage.
const CLEANUP_EVENTS: usize = 6;
const RECEIPT_BYTES: usize = 8192;

#[derive(Debug)]
struct LifecycleEngine {
    pipeline: Arc<ExtensionPipelineV1>,
    config_digests: Vec<crawlx_core::hash::Digest>,
    limits: ExtensionEventLimitsV1,
    trail: Vec<ExtensionReceiptV1>,
    count: usize,
    bytes: usize,
    sequence: u64,
    sealed: bool,
    terminal: Option<ExtensionTerminalV1>,
    reason: Option<ExtensionReasonV1>,
    skipped: bool,
    policy_denied: bool,
    prepared: bool,
    refused_events: u64,
}
fn lock_engine(engine: &Mutex<LifecycleEngine>) -> MutexGuard<'_, LifecycleEngine> {
    // No callback reenters this mutex. Poisoning narrows admission to denial.
    match engine.lock() {
        Ok(engine) => engine,
        Err(poisoned) => {
            let mut engine = poisoned.into_inner();
            engine.policy_denied = true;
            engine.reason = Some(ExtensionReasonV1::PolicyDenied);
            engine.skipped = true;
            engine
        }
    }
}
fn result_error(result: &ExtensionResultV1) -> Result<(), ExtensionError> {
    match result {
        ExtensionResultV1::Skip(ExtensionReasonV1::PolicyDenied) => Err(ExtensionError::PolicyDenied),
        ExtensionResultV1::Skip(ExtensionReasonV1::Cancelled) => Err(ExtensionError::Cancelled),
        ExtensionResultV1::Skip(ExtensionReasonV1::Capacity)
        | ExtensionResultV1::Fail(ExtensionReasonV1::Capacity) => Err(ExtensionError::Limit),
        ExtensionResultV1::Skip(_) => Err(ExtensionError::Rejected),
        ExtensionResultV1::Fail(_) => Err(ExtensionError::Failed),
        _ => Ok(()),
    }
}
impl LifecycleEngine {
    fn sticky_result(&self) -> ExtensionResultV1 {
        match self.reason {
            Some(reason) if self.skipped => ExtensionResultV1::Skip(reason),
            Some(reason) => ExtensionResultV1::Fail(reason),
            None => ExtensionResultV1::Continue,
        }
    }
    fn remember(&mut self, result: &ExtensionResultV1) {
        match result {
            ExtensionResultV1::Skip(ExtensionReasonV1::PolicyDenied)
            | ExtensionResultV1::Fail(ExtensionReasonV1::PolicyDenied) => {
                self.policy_denied = true;
                self.reason = Some(ExtensionReasonV1::PolicyDenied);
                self.skipped = true;
            }
            ExtensionResultV1::Skip(reason) if self.reason.is_none() => {
                self.reason = Some(*reason);
                self.skipped = true;
            }
            ExtensionResultV1::Fail(reason) if self.reason.is_none() => {
                self.reason = Some(*reason);
                self.skipped = false;
            }
            _ => {}
        }
    }
    fn execute(
        &mut self,
        event: ExtensionEventV1,
        cleanup: bool,
    ) -> Result<ExtensionResultV1, ExtensionError> {
        if !cleanup && self.sealed {
            return Err(ExtensionError::Closed);
        }
        if !cleanup
            && (self.count >= self.limits.events - CLEANUP_EVENTS
                || self.bytes > self.limits.bytes - CLEANUP_EVENTS * RECEIPT_BYTES - RECEIPT_BYTES)
        {
            self.refused_events = self.refused_events.saturating_add(1);
            self.remember(&ExtensionResultV1::Fail(ExtensionReasonV1::Capacity));
            return Err(ExtensionError::Limit);
        }
        if let ExtensionEventV1::HeadersReceived(facts) = &event {
            facts.validate()?;
        }
        let stage = event.stage();
        // Candidate transforms and replacement proposals execute at their typed data
        // boundaries below. Never claim those callbacks ran from a metadata-only event.
        let mut registrations: Vec<_> = self
            .pipeline
            .extensions
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.stage == stage
                    && matches!(
                        &entry.config,
                        ExtensionConfigV1::ReadOnly {}
                            | ExtensionConfigV1::HeaderPolicy { .. }
                            | ExtensionConfigV1::Annotate { .. }
                            | ExtensionConfigV1::FailStage { .. }
                            | ExtensionConfigV1::RejectStage { .. }
                    )
            })
            .collect();
        registrations.sort_by_key(|(_, entry)| entry.order);
        if self.pipeline.reverse_response
            && !matches!(
                stage,
                ExtensionStageV1::Configure
                    | ExtensionStageV1::RequestProposed
                    | ExtensionStageV1::BeforeAcquisition
                    | ExtensionStageV1::BrowserPreLaunch
                    | ExtensionStageV1::BrowserPostLaunch
                    | ExtensionStageV1::BrowserPageCreate
                    | ExtensionStageV1::BrowserPreNavigation
            )
        {
            registrations.reverse();
        }
        let input_bytes = json_size(&event)?;
        let mut callbacks = Vec::with_capacity(registrations.len());
        for (registration, entry) in registrations {
            let mut output = if input_bytes > entry.limits.input_bytes {
                ExtensionResultV1::Fail(ExtensionReasonV1::Capacity)
            } else {
                match (&entry.config, &event) {
                    (
                        ExtensionConfigV1::ReadOnly {},
                        ExtensionEventV1::RequestProposed { read_only: false },
                    ) => ExtensionResultV1::Skip(ExtensionReasonV1::PolicyDenied),
                    (
                        ExtensionConfigV1::HeaderPolicy { policy },
                        ExtensionEventV1::HeadersReceived(facts),
                    ) => {
                        if policy.check(facts).is_ok() {
                            ExtensionResultV1::Continue
                        } else {
                            ExtensionResultV1::Skip(ExtensionReasonV1::Rejected)
                        }
                    }
                    (ExtensionConfigV1::Annotate { code, .. }, _) => {
                        ExtensionResultV1::Annotation(code.clone())
                    }
                    (ExtensionConfigV1::FailStage { .. }, _) => {
                        ExtensionResultV1::Fail(ExtensionReasonV1::HandlerFailed)
                    }
                    (ExtensionConfigV1::RejectStage { .. }, _) => {
                        ExtensionResultV1::Skip(ExtensionReasonV1::Rejected)
                    }
                    _ => ExtensionResultV1::Continue,
                }
            };
            if json_size(&output)? > entry.limits.output_bytes {
                output = ExtensionResultV1::Fail(ExtensionReasonV1::Capacity);
            }
            callbacks.push(ExtensionCallbackReceiptV1::new(
                registration,
                self.config_digests[registration],
                output,
            ));
        }
        for callback in &callbacks {
            self.remember(&callback.result);
        }
        let result = self.sticky_result();
        let sequence = self.sequence.checked_add(1).ok_or(ExtensionError::Limit)?;
        let receipt = ExtensionReceiptV1::new(sequence, event, callbacks, result.clone());
        let bytes = json_size(&receipt)?;
        if bytes > RECEIPT_BYTES
            || self
                .bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.limits.bytes)
            || self.count >= self.limits.events
        {
            self.refused_events = self.refused_events.saturating_add(1);
            self.remember(&ExtensionResultV1::Fail(ExtensionReasonV1::Capacity));
            return Err(ExtensionError::Limit);
        }
        self.bytes += bytes;
        self.count += 1;
        self.sequence = sequence;
        self.trail.push(receipt);
        Ok(result)
    }
    fn finish(&mut self, requested: ExtensionTerminalV1) -> Result<bool, ExtensionError> {
        if self.sealed {
            return Ok(false);
        }
        self.sealed = true;
        match requested {
            ExtensionTerminalV1::Skipped(reason) => self.remember(&ExtensionResultV1::Skip(reason)),
            ExtensionTerminalV1::Failed(reason) => self.remember(&ExtensionResultV1::Fail(reason)),
            _ => {}
        }
        if let Some(reason) = self.reason {
            self.execute(ExtensionEventV1::Error(reason), true)?;
            let reason = self.reason.unwrap_or(reason);
            let skipped = matches!(self.sticky_result(), ExtensionResultV1::Skip(_));
            self.execute(
                if skipped {
                    ExtensionEventV1::Skipped(reason)
                } else {
                    ExtensionEventV1::Failed(reason)
                },
                true,
            )?;
        }
        let outcome = match self.sticky_result() {
            ExtensionResultV1::Skip(reason) => ExtensionTerminalV1::Skipped(reason),
            ExtensionResultV1::Fail(reason) => ExtensionTerminalV1::Failed(reason),
            _ => ExtensionTerminalV1::Completed,
        };
        self.terminal = Some(outcome);
        // Once chosen, terminal outcome is immutable even if a cleanup callback fails.
        self.execute(ExtensionEventV1::Terminal(outcome), true)?;
        self.execute(ExtensionEventV1::Checkpoint, true)?;
        self.execute(ExtensionEventV1::Close, true)?;
        Ok(true)
    }
}
impl RequestLifecycle {
    /// Resolve immutable compiled descriptors and execute configure callbacks.
    ///
    /// # Errors
    /// Rejects unknown implementations, mutable duplicates or invalid bounds.
    pub fn new(pipeline: &ExtensionPipelineV1) -> Result<Self, ExtensionError> {
        Self::with_limits(pipeline, ExtensionEventLimitsV1::default())
    }
    /// Construct a lifecycle with explicit total trail limits.
    ///
    /// # Errors
    /// Rejects malformed descriptors or bounds; callback failures remain sticky until finalization.
    pub fn with_limits(
        pipeline: &ExtensionPipelineV1,
        limits: ExtensionEventLimitsV1,
    ) -> Result<Self, ExtensionError> {
        pipeline.validate()?;
        ExtensionEventLimitsV1::new(limits.events, limits.bytes)?;
        let pipeline = Arc::new(pipeline.clone());
        let config_digests = pipeline
            .extensions
            .iter()
            .map(|entry| entry.config_digest())
            .collect::<Result<Vec<_>, ExtensionError>>()?;
        let mut engine = LifecycleEngine {
            pipeline: Arc::clone(&pipeline),
            limits,
            trail: Vec::new(),
            count: 0,
            config_digests,
            bytes: 0,
            sequence: 0,
            sealed: false,
            terminal: None,
            reason: None,
            skipped: false,
            policy_denied: false,
            prepared: false,
            refused_events: 0,
        };
        engine.execute(ExtensionEventV1::Configure, false)?;
        let engine = Arc::new(Mutex::new(engine));
        let owner = Arc::new(LifecycleOwner {
            engine: Arc::clone(&engine),
        });
        Ok(Self {
            entered: Vec::with_capacity(pipeline.extensions.len()),
            cleanup: Vec::new(),
            pipeline,
            engine,
            _owner: owner,
        })
    }
    /// Dispatch a typed callback boundary. Terminal/cleanup events are owned by `finish`.
    ///
    /// # Errors
    /// Rejects reserved events, sealed lifecycle, cancellation and resource overflow.
    pub fn dispatch(
        &mut self,
        event: ExtensionEventV1,
        cancel: &CancellationToken,
    ) -> Result<ExtensionResultV1, ExtensionError> {
        if matches!(
            event,
            ExtensionEventV1::Configure
                | ExtensionEventV1::Error(_)
                | ExtensionEventV1::Skipped(_)
                | ExtensionEventV1::Failed(_)
                | ExtensionEventV1::Terminal(_)
                | ExtensionEventV1::Checkpoint
                | ExtensionEventV1::Close
        ) {
            return Err(ExtensionError::Closed);
        }
        let mut engine = lock_engine(&self.engine);
        if engine.policy_denied {
            return Err(ExtensionError::PolicyDenied);
        }
        if engine.sealed {
            return Err(ExtensionError::Closed);
        }
        if cancel.is_cancelled() {
            engine.remember(&ExtensionResultV1::Skip(ExtensionReasonV1::Cancelled));
            return Err(ExtensionError::Cancelled);
        }
        engine.execute(event, false)
    }
    /// Execute request middleware forward. Replacements still require native re-admission.
    ///
    /// # Errors
    /// Returns cancellation, policy denial, callback failure, invalid intent or capacity refusal.
    pub fn before_acquisition(
        &mut self,
        request: &RequestEnvelopeV1,
        cancellation: &CancellationToken,
    ) -> Result<RequestPreparationV1, ExtensionError> {
        {
            let mut engine = lock_engine(&self.engine);
            if engine.policy_denied {
                return Err(ExtensionError::PolicyDenied);
            }
            if engine.prepared || engine.sealed {
                return Err(ExtensionError::Closed);
            }
            engine.prepared = true;
        }
        request.validate().map_err(|_| ExtensionError::Rejected)?;
        let result = self.dispatch(
            ExtensionEventV1::RequestProposed {
                read_only: matches!(request.method.as_str(), "GET" | "HEAD"),
            },
            cancellation,
        )?;
        result_error(&result)?;
        let route = self.pipeline.route(&request.route)?;
        let result = self.dispatch(ExtensionEventV1::BeforeAcquisition, cancellation)?;
        result_error(&result)?;
        let mut replacement = None;
        let request_bytes = json_size(request)?;
        for entry in self.pipeline.ordered() {
            if !matches!(
                entry.stage,
                ExtensionStageV1::RequestProposed | ExtensionStageV1::BeforeAcquisition
            ) {
                continue;
            }
            let started = Instant::now();
            guard(cancellation, started, entry.limits.deadline_ms)?;
            if request_bytes > entry.limits.input_bytes {
                return Err(ExtensionError::Limit);
            }
            self.entered.push(entry.id.clone());
            if let ExtensionConfigV1::ReplaceRequest { request: proposed } = &entry.config {
                if !same_intent(proposed, request) {
                    if replacement.is_some() || json_size(proposed)? > entry.limits.output_bytes {
                        return Err(ExtensionError::Limit);
                    }
                    replacement = Some(proposed.as_ref().clone());
                }
            }
            guard(cancellation, started, entry.limits.deadline_ms)?;
        }
        Ok(RequestPreparationV1 { replacement, route })
    }
    /// Seal and execute error, failed/skipped, terminal, checkpoint and close callbacks once.
    ///
    /// # Errors
    /// Returns accounting/serialization refusal; cleanup does not depend on cancellation.
    pub fn finish(&mut self, outcome: ExtensionTerminalV1) -> Result<bool, ExtensionError> {
        let first = lock_engine(&self.engine).finish(outcome)?;
        if first {
            self.entered.reverse();
            self.cleanup = std::mem::take(&mut self.entered);
        }
        Ok(first)
    }
    /// Seal and transfer the trail under one lock for an attempt's fenced commit.
    ///
    /// # Errors
    /// Returns bounded finalization/serialization refusal without fabricating receipts.
    pub fn finish_and_drain(
        &mut self,
        outcome: ExtensionTerminalV1,
    ) -> Result<(bool, Vec<ExtensionReceiptV1>), ExtensionError> {
        let (first, receipts) = {
            let mut engine = lock_engine(&self.engine);
            let first = engine.finish(outcome)?;
            (first, std::mem::take(&mut engine.trail))
        };
        if first {
            self.entered.reverse();
            self.cleanup = std::mem::take(&mut self.entered);
        }
        Ok((first, receipts))
    }
    /// Compatibility finalizer; typed callers should supply the actual outcome to `finish`.
    #[must_use]
    pub fn finalize(&mut self, policy_denied: bool) -> bool {
        {
            let mut engine = lock_engine(&self.engine);
            if engine.sealed {
                return false;
            }
            if policy_denied {
                engine.remember(&ExtensionResultV1::Skip(ExtensionReasonV1::PolicyDenied));
            }
        }
        self.finish(ExtensionTerminalV1::Completed).unwrap_or(false)
    }
    /// Actual bounded event receipts, suitable for fenced persistence after privacy admission.
    #[must_use]
    pub fn events(&self) -> Vec<ExtensionReceiptV1> {
        lock_engine(&self.engine).trail.clone()
    }
    /// Transfer receipts without resetting cumulative sequence/count/byte allowances.
    #[must_use]
    pub fn drain_events(&mut self) -> Vec<ExtensionReceiptV1> {
        std::mem::take(&mut lock_engine(&self.engine).trail)
    }
    /// Immutable terminal outcome, chosen once.
    #[must_use]
    pub fn terminal(&self) -> Option<ExtensionTerminalV1> {
        lock_engine(&self.engine).terminal
    }
    /// Cumulative count, serialized byte usage and refused-event count; draining never resets them.
    #[must_use]
    pub fn event_usage(&self) -> (usize, usize, u64) {
        let engine = lock_engine(&self.engine);
        (engine.count, engine.bytes, engine.refused_events)
    }
    /// Acquisition-time gate sharing this lifecycle's bounded dispatcher and receipts.
    #[must_use]
    pub fn header_gate(&self) -> Arc<dyn crawlx_fetch::client::ResponseHeaderGate> {
        Arc::new(LifecycleHeaderGate {
            engine: Arc::clone(&self.engine),
        })
    }
    /// Ordered local cleanup receipt, bounded by descriptor count.
    #[must_use]
    pub fn cleanup_order(&self) -> &[String] {
        &self.cleanup
    }
    /// Native denial cannot be erased by callback output.
    #[must_use]
    pub fn policy_denied(&self) -> bool {
        lock_engine(&self.engine).policy_denied
    }
    /// Validate an entire undrained replay by reexecuting compiled callbacks.
    ///
    /// # Errors
    /// Rejects gaps, tampering, invalid ordering, duplicate terminal outcomes and overflow.
    pub fn validate_replay(
        pipeline: &ExtensionPipelineV1,
        limits: ExtensionEventLimitsV1,
        receipts: &[ExtensionReceiptV1],
    ) -> Result<(), ExtensionError> {
        crawlx_core::extensions::validate_extension_receipts(receipts)?;
        let mut lifecycle = Self::with_limits(pipeline, limits)?;
        if receipts.first() != lifecycle.events().first() {
            return Err(ExtensionError::Rejected);
        }
        let terminal = receipts
            .iter()
            .find_map(|receipt| match receipt.event {
                ExtensionEventV1::Terminal(outcome) => Some(outcome),
                _ => None,
            })
            .ok_or(ExtensionError::Rejected)?;
        for receipt in receipts.iter().skip(1) {
            if matches!(
                receipt.event,
                ExtensionEventV1::Error(_) | ExtensionEventV1::Terminal(_)
            ) {
                break;
            }
            if matches!(
                receipt.event,
                ExtensionEventV1::Configure
                    | ExtensionEventV1::Skipped(_)
                    | ExtensionEventV1::Failed(_)
                    | ExtensionEventV1::Checkpoint
                    | ExtensionEventV1::Close
            ) {
                return Err(ExtensionError::Rejected);
            }
            lock_engine(&lifecycle.engine).execute(receipt.event.clone(), false)?;
        }
        lifecycle.finish(terminal)?;
        if lifecycle.events() != receipts {
            return Err(ExtensionError::Rejected);
        }
        Ok(())
    }
}
impl Drop for LifecycleOwner {
    fn drop(&mut self) {
        let _ = lock_engine(&self.engine).finish(ExtensionTerminalV1::Skipped(ExtensionReasonV1::Cancelled));
    }
}
struct LifecycleHeaderGate {
    engine: Arc<Mutex<LifecycleEngine>>,
}
impl std::fmt::Debug for LifecycleHeaderGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fetch option diagnostics must never expand replacement configuration.
        formatter
            .debug_struct("LifecycleHeaderGate")
            .finish_non_exhaustive()
    }
}
impl crawlx_fetch::client::ResponseHeaderGate for LifecycleHeaderGate {
    fn check(
        &self,
        status: u16,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<(), crawlx_fetch::FetchError> {
        let mut engine = lock_engine(&self.engine);
        if engine.sealed || engine.reason.is_some() {
            return Err(crawlx_fetch::FetchError::ExtensionHeaderSkipped);
        }
        let facts = match HeaderFactsV1::new(status, content_type, content_length) {
            Ok(facts) => facts,
            Err(_) => {
                engine.remember(&ExtensionResultV1::Skip(ExtensionReasonV1::Rejected));
                return Err(crawlx_fetch::FetchError::ExtensionHeaderSkipped);
            }
        };
        let result = engine
            .execute(ExtensionEventV1::HeadersReceived(facts), false)
            .map_err(|_| crawlx_fetch::FetchError::ExtensionHeaderSkipped)?;
        result_error(&result).map_err(|_| crawlx_fetch::FetchError::ExtensionHeaderSkipped)
    }
}
/// Typed lossless result reference or one skip per monotonically increasing decision.
/// Committed values reference durable items; this channel never owns their only copy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionStreamResultV1 {
    /// A durable accepted-item reference, never an ephemeral content value.
    Committed {
        /// Stable accepted-item digest.
        item: crawlx_core::hash::Digest,
    },
    /// One decision's typed skip.
    Skipped {
        /// Strictly increasing decision number within this stream.
        decision: u64,
        /// Content-free refusal.
        reason: ExtensionReasonV1,
    },
}
/// Failed sends return ownership, including durable accepted-item references.
#[derive(Debug, thiserror::Error)]
#[error("extension result stream refused an item")]
#[non_exhaustive]
pub struct ExtensionStreamSendError {
    /// Original unsent value. Callers can retry persistence/delivery without losing it.
    pub item: ExtensionStreamResultV1,
    /// Typed send refusal.
    #[source]
    pub source: ExtensionError,
}
/// Single ordered bounded producer. Intentionally not clonable.
#[derive(Debug)]
#[non_exhaustive]
pub struct ExtensionResultSender {
    sender: mpsc::Sender<ExtensionStreamResultV1>,
    cancel: CancellationToken,
    last_skip: Option<u64>,
}
/// Single consumer; cancellation closes admission but drains already queued outcomes.
#[derive(Debug)]
#[non_exhaustive]
pub struct ExtensionResultReceiver {
    receiver: mpsc::Receiver<ExtensionStreamResultV1>,
    cancel: CancellationToken,
}
/// Construct a typed bounded result/skip stream without spawning detached tasks.
///
/// # Errors
/// Rejects zero or excessive queue capacities.
pub fn extension_result_channel(
    capacity: usize,
    cancel: CancellationToken,
) -> Result<(ExtensionResultSender, ExtensionResultReceiver), ExtensionError> {
    if !(1..=4096).contains(&capacity) {
        return Err(ExtensionError::Limit);
    }
    let (sender, receiver) = mpsc::channel(capacity);
    Ok((
        ExtensionResultSender {
            sender,
            cancel: cancel.clone(),
            last_skip: None,
        },
        ExtensionResultReceiver { receiver, cancel },
    ))
}
impl ExtensionResultSender {
    /// Await consumer capacity. Cancellation returns the unsent item without leaking a permit.
    ///
    /// # Errors
    /// Returns original value on cancellation, closed receiver or duplicate/out-of-order skip.
    pub async fn send(&mut self, item: ExtensionStreamResultV1) -> Result<(), ExtensionStreamSendError> {
        let decision = match &item {
            ExtensionStreamResultV1::Skipped { decision, .. } => Some(*decision),
            _ => None,
        };
        if decision.is_some_and(|value| self.last_skip.is_some_and(|last| value <= last)) {
            return Err(ExtensionStreamSendError {
                item,
                source: ExtensionError::Rejected,
            });
        }
        let permit = tokio::select! {
            biased;
            () = self.cancel.cancelled() => {
                return Err(ExtensionStreamSendError { item, source: ExtensionError::Cancelled });
            }
            permit = self.sender.reserve() => match permit {
                Ok(permit) => permit,
                Err(_) => return Err(ExtensionStreamSendError { item, source: ExtensionError::Closed }),
            },
        };
        // No await after reservation: accepted outcomes cannot be lost between reserve and send.
        permit.send(item);
        if let Some(decision) = decision {
            self.last_skip = Some(decision);
        }
        Ok(())
    }
}
impl ExtensionResultReceiver {
    /// Receive with backpressure. Cancellation seals the queue, then drains committed values.
    pub async fn recv(&mut self) -> Option<ExtensionStreamResultV1> {
        if self.cancel.is_cancelled() {
            self.receiver.close();
            return self.receiver.recv().await;
        }
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => {
                self.receiver.close();
                self.receiver.recv().await
            }
            item = self.receiver.recv() => item,
        }
    }
    /// Stop new sends while preserving queued accepted outcomes for draining.
    pub fn close(&mut self) {
        self.receiver.close();
    }
}
fn guard(cancel: &CancellationToken, started: Instant, deadline_ms: u32) -> Result<(), ExtensionError> {
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    if started.elapsed() >= Duration::from_millis(u64::from(deadline_ms)) {
        return Err(ExtensionError::Deadline);
    }
    Ok(())
}
fn same_intent(a: &RequestEnvelopeV1, b: &RequestEnvelopeV1) -> bool {
    // Provenance is assigned by native admission, never by a replacement descriptor.
    a.url.url == b.url.url
        && a.method == b.method
        && a.header_control == b.header_control
        && a.body == b.body
        && a.route == b.route
        && a.metadata == b.metadata
        && a.priority == b.priority
        && a.dialect == b.dialect
        && a.source_key == b.source_key
        && a.revisit_generation == b.revisit_generation
        && a.session_generation == b.session_generation
        && a.not_before == b.not_before
}
fn candidate_failure(policy: ExtensionFailurePolicyV1) -> ExtensionError {
    match policy {
        ExtensionFailurePolicyV1::Reject => ExtensionError::Rejected,
        ExtensionFailurePolicyV1::Fail => ExtensionError::Failed,
        _ => ExtensionError::Failed,
    }
}
/// Shared borrowed-envelope native item pipeline, suitable inside an existing CPU job.
///
/// # Errors
/// Refuses unknown labels, cancellation, deadlines, rejected candidates and byte limits.
/// Output is ephemeral content, not an accepted durable item or a delivery destination.
pub fn transform_document(
    pipeline: &ExtensionPipelineV1,
    label: &str,
    document: &DocumentEnvelopeV1,
    cancel: &CancellationToken,
) -> Result<Option<Value>, ExtensionError> {
    pipeline.validate()?;
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    if pipeline.route(label)? == HandlerV1::Skip {
        return Ok(None);
    }
    if document.privacy_projection_version != Some(1) {
        return Err(ExtensionError::Rejected);
    }
    if document.quality.status != QualityStatusV1::Accepted {
        return Err(pipeline
            .extensions
            .iter()
            .find(|e| matches!(e.config, ExtensionConfigV1::RequireQuality {}))
            .map_or(ExtensionError::Rejected, |e| candidate_failure(e.failure_policy)));
    }
    let mut item = document_item(document, MAX_EXTENSION_BYTES)?;
    let mut item_bytes = json_size(&item)?;
    let mut entries = pipeline.ordered();
    if pipeline.reverse_response {
        entries.reverse();
    }
    for stage in [ExtensionStageV1::Parse, ExtensionStageV1::Item] {
        for entry in entries.iter().filter(|e| e.stage == stage) {
            let started = Instant::now();
            guard(cancel, started, entry.limits.deadline_ms)?;
            if entry.limits.items == 0 || item_bytes > entry.limits.input_bytes {
                return Err(ExtensionError::Limit);
            }
            match &entry.config {
                ExtensionConfigV1::RequireQuality {}
                    if document.quality.status != QualityStatusV1::Accepted =>
                {
                    return Err(candidate_failure(entry.failure_policy));
                }
                ExtensionConfigV1::TrimTitle {} => {
                    if let Some(Value::String(title)) = item.get_mut("title") {
                        let start = title.len().saturating_sub(title.trim_start().len());
                        let end = title.trim_end().len();
                        if start >= end {
                            title.clear();
                        } else {
                            title.truncate(end);
                            title.drain(..start);
                        }
                    }
                    item_bytes = json_size(&item)?;
                }
                ExtensionConfigV1::RequireTitle {}
                    if item
                        .get("title")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty) =>
                {
                    return Err(candidate_failure(entry.failure_policy));
                }
                ExtensionConfigV1::FailStage { .. } => return Err(ExtensionError::Failed),
                ExtensionConfigV1::RejectStage { .. } => return Err(ExtensionError::Rejected),
                _ => {}
            }
            if item_bytes > entry.limits.output_bytes {
                return Err(ExtensionError::Limit);
            }
            guard(cancel, started, entry.limits.deadline_ms)?;
        }
    }
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    Ok(Some(item))
}
/// Run the pure pipeline through the shared worker CPU pool without cloning a body.
/// Cancellation never releases a running blocking closure's CPU permit early.
///
/// # Errors
/// Returns typed transform failures, cancellation or CPU task failure. Trusted work
/// checks cancellation at each bounded stage and remains charged until it exits.
pub async fn process_document(
    pool: &CpuPool,
    pipeline: ExtensionPipelineV1,
    label: String,
    document: DocumentEnvelopeV1,
    cancel: CancellationToken,
) -> Result<Option<Value>, ExtensionError> {
    pipeline.validate()?;
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    let deadline_ms = pipeline
        .extensions
        .iter()
        .map(|e| u64::from(e.limits.deadline_ms))
        .sum::<u64>()
        .max(1000);
    let token = cancel.child_token();
    let _cancel_on_drop = token.clone().drop_guard();
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ExtensionError::Cancelled),
        result = tokio::time::timeout(Duration::from_millis(deadline_ms),
            pool.run(move || transform_document(&pipeline, &label, &document, &token))) => {
            result.map_err(|_| ExtensionError::Deadline)?.map_err(|_| ExtensionError::Task)?
        }
    }
}

/// Store one transformed candidate through the typed content/privacy gateway.
/// Dataset append is explicit; undeclared namespaces never receive implicit writes.
///
/// # Errors
/// Returns serialization, retention, schema, expiry or artifact backend failures.
#[allow(clippy::too_many_arguments)]
pub async fn store_candidate(
    artifacts: &dyn crawlx_core::repo::ArtifactStore,
    cpu: &crate::runtime::CpuPool,
    run: &crawlx_core::repo::CrawlRun,
    page: i64,
    candidate: &Value,
    extractor: &str,
    controls: &crawlx_core::request_controls::RequestControls,
    captcha: &crawlx_core::captcha::CaptchaSecrets,
) -> Result<
    (
        crawlx_core::ArtifactRef,
        Option<crawlx_core::dataset::AcceptedBatchV1>,
        Vec<crawlx_core::dataset::DeliveryBatchV1>,
    ),
    crawlx_core::StoreError,
> {
    use crawlx_core::{
        dataset::{AcceptedBatchV1, AcceptedItemV1},
        secret::ArtifactSink,
        StoreError,
    };
    if json_size(candidate).map_err(|_| StoreError::Serialization("invalid item JSON".into()))?
        > MAX_EXTENSION_BYTES
    {
        return Err(StoreError::Conflict("extension item byte limit".into()));
    }
    let mut projected = candidate.clone();
    project_candidate(&mut projected, controls, captcha)?;
    let mut bytes = serde_json::to_vec(&projected).map_err(|e| StoreError::Serialization(e.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_EXTENSION_BYTES {
        return Err(StoreError::Conflict("extension item byte limit".into()));
    }
    let approved = crawlx_core::secret::Redactor::new().redact_artifact(&bytes)?;
    if approved.as_ref().len() > MAX_EXTENSION_BYTES {
        return Err(StoreError::Conflict("extension item byte limit".into()));
    }
    let size = u64::try_from(approved.as_ref().len())
        .map_err(|_| StoreError::Conflict("extension item byte limit".into()))?;
    let artifact = ArtifactSink::over(artifacts)
        .put_dataset(
            run.id,
            page,
            "extension_item",
            "application/vnd.crawlx.item+json",
            &approved,
        )
        .await?;
    let Some(dataset) = &run.config.extensions.dataset else {
        return Ok((artifact, None, Vec::new()));
    };
    let declaration = run
        .config
        .datasets
        .stores
        .iter()
        .find(|s| &s.name == dataset)
        .ok_or_else(|| StoreError::Conflict("extension dataset not declared".into()))?;
    if declaration.schema_version != "document_item_v1" {
        return Err(StoreError::Conflict("extension dataset schema mismatch".into()));
    }
    let content = artifacts.dataset_content(run.id, page, &artifact, size).await?;
    let expires = content
        .expires_at()
        .or_else(|| {
            run.created_at
                .checked_add_signed(chrono::Duration::days(i64::from(run.config.retention.days)))
        })
        .ok_or_else(|| StoreError::RetentionDenied("item expiry unavailable".into()))?;
    let mut item = AcceptedItemV1::new(
        format!("request-{page}"),
        "native_pipeline_v1".into(),
        declaration.schema_version.clone(),
        extractor.replace('/', "."),
        content,
        size,
    );
    item.expires_at = Some(expires);
    let outbox =
        crate::delivery::prepare_item_feeds(artifacts, cpu, run, page, dataset, &artifact, approved).await?;
    let outbox = crate::delivery::take_feed_fragments(run, &mut item, outbox);
    Ok((
        artifact,
        Some(AcceptedBatchV1::new(dataset.clone(), vec![item])),
        outbox,
    ))
}

fn project_candidate(
    value: &mut Value,
    controls: &crawlx_core::request_controls::RequestControls,
    captcha: &crawlx_core::captcha::CaptchaSecrets,
) -> Result<(), crawlx_core::StoreError> {
    fn strings(value: &mut Value, controls: &crawlx_core::request_controls::RequestControls) {
        let scrub = |text: &str| {
            String::from_utf8_lossy(
                &crawlx_telemetry::Redactor::new().scrub_bytes(text.as_bytes(), controls.secret_values()),
            )
            .into_owned()
        };
        match value {
            Value::String(text) => *text = scrub(text),
            Value::Array(values) => {
                for value in values {
                    strings(value, controls);
                }
            }
            Value::Object(fields) => {
                *fields = std::mem::take(fields)
                    .into_iter()
                    .map(|(key, mut value)| {
                        strings(&mut value, controls);
                        (scrub(&key), value)
                    })
                    .collect();
            }
            _ => {}
        }
    }
    strings(value, controls);
    captcha.redact_json(value).map_err(|_| {
        crawlx_core::StoreError::RetentionDenied("item dynamic-secret projection unavailable".into())
    })?;
    let valid = value.as_object().is_some_and(|fields| {
        fields.len() == 5
            && fields
                .get("title")
                .is_some_and(|v| v.is_null() || v.as_str().is_some())
            && fields
                .get("language")
                .is_some_and(|v| v.is_null() || v.as_str().is_some())
            && fields.get("extractor").and_then(Value::as_str).is_some()
            && fields.get("quality").and_then(Value::as_str) == Some("accepted")
            && fields.get("authors").is_some_and(|v| {
                v.is_null()
                    || v.as_array()
                        .is_some_and(|a| a.len() <= 64 && a.iter().all(Value::is_string))
            })
    });
    if !valid {
        return Err(crawlx_core::StoreError::Conflict(
            "projected item schema rejected".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #[tokio::test]
    async fn split_markup_credentials_and_live_tokens_are_projected_before_item_schema() {
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch.extra_headers.insert("x-custom", "hdrCanary742");
        fetch
            .cookies
            .push(crawlx_core::request_controls::FetchCookie::new(
                "session",
                "cookieCanary853",
            ));
        let controls = crawlx_core::request_controls::RequestControls::resolve(&fetch, "fixture.test", None)
            .await
            .unwrap();
        let captcha = crawlx_core::captcha::CaptchaSecrets::default();
        captcha
            .register(crawlx_core::secret::SecretOr::secret("captchaCanary953".into()))
            .unwrap();
        let base = url::Url::parse("https://fixture.test/article").unwrap();
        let options = crawlx_extract::ExtractOptions {
            content: Some(crawlx_core::extraction::ExtractionPolicyV1::default()),
            acquisition_validation: Some(crate::acquisition::context(
                &crawlx_core::acquisition::AcquisitionPolicyV1::default(),
                Some(200),
                false,
            )),
            ..crawlx_extract::ExtractOptions::default()
        };
        let doc = crate::acquisition::extract_document_with_secrets(
            b"<html><body><article><h1>hdrCanary<span>742</span> cookieCanary<i>853</i> captchaCanary<b>953</b></h1><p>A complete native privacy fixture paragraph with enough text for article selection.</p></article></body></html>",
            &base, &options, &controls, &captcha).unwrap();
        let mut item = transform_document(
            &ExtensionPipelineV1::default(),
            "default",
            doc.article.as_ref().unwrap(),
            &CancellationToken::new(),
        )
        .unwrap()
        .unwrap();
        project_candidate(&mut item, &controls, &captcha).unwrap();
        let encoded = serde_json::to_string(&item).unwrap();
        for secret in ["hdrCanary742", "cookieCanary853", "captchaCanary953"] {
            assert!(!doc.text.contains(secret));
            assert!(!encoded.contains(secret));
        }
        assert_eq!(item["quality"], "accepted");
    }
    use super::*;
    use crawlx_core::{
        extensions::ExtensionSpecV1,
        extraction::{ArticleMetadataV1, QualityOutcomeV1},
        hash::Digest,
    };
    fn document(title: &str) -> DocumentEnvelopeV1 {
        let mut metadata = ArticleMetadataV1::default();
        metadata.title.value = Some(title.into());
        let mut document = DocumentEnvelopeV1::new(
            Digest([0; 32]),
            Digest([0; 32]),
            "fixture".into(),
            0,
            Vec::new(),
            metadata,
            QualityOutcomeV1::new(QualityStatusV1::Accepted, Vec::new(), 0, 0, 0),
        );
        document.privacy_projection_version = Some(1);
        document
    }
    fn request(path: &str) -> RequestEnvelopeV1 {
        let url = url::Url::parse(&format!("https://fixture.test/{path}")).unwrap();
        let canonical = crawlx_url::Canonicalizer::canonicalize_detailed(
            url.as_str(),
            &url,
            &crawlx_url::CanonicalizeOptions::default(),
        )
        .unwrap();
        RequestEnvelopeV1::get(canonical.url, 0, None)
    }
    #[test]
    fn replacement_is_a_proposal_and_does_not_rewrite_or_repeat_the_leased_intent() {
        let original = request("old");
        let mut pipeline = ExtensionPipelineV1::default();
        let proposed = request("new");
        pipeline.extensions.push(ExtensionSpecV1::new(
            ExtensionConfigV1::ReplaceRequest {
                request: Box::new(proposed.clone()),
            },
            0,
        ));
        let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
        let prepared = lifecycle
            .before_acquisition(&original, &CancellationToken::new())
            .unwrap();
        assert_eq!(original.url.url.path(), "/old");
        assert_eq!(prepared.replacement.unwrap().url.url.path(), "/new");
        let mut admitted = proposed;
        admitted.parent = Some(42);
        admitted.depth = 1;
        let mut next = RequestLifecycle::new(&pipeline).unwrap();
        assert!(next
            .before_acquisition(&admitted, &CancellationToken::new())
            .unwrap()
            .replacement
            .is_none());
    }
    #[test]
    fn request_policy_denial_wins_after_close_and_cancellation() {
        let mut pipeline = ExtensionPipelineV1::default();
        pipeline
            .extensions
            .push(ExtensionSpecV1::new(ExtensionConfigV1::ReadOnly {}, 0));
        let mut request = request("write");
        request.method = "POST".into();
        let cancel = CancellationToken::new();
        let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
        assert!(matches!(
            lifecycle.before_acquisition(&request, &cancel),
            Err(ExtensionError::PolicyDenied)
        ));
        assert!(lifecycle.finalize(false));
        cancel.cancel();
        assert!(matches!(
            lifecycle.before_acquisition(&request, &cancel),
            Err(ExtensionError::PolicyDenied)
        ));
    }
    #[test]
    fn forward_and_reverse_order_changes_real_candidate_result() {
        let mut pipeline = ExtensionPipelineV1::default();
        pipeline.extensions = vec![
            ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0),
            ExtensionSpecV1::new(ExtensionConfigV1::RequireTitle {}, 1),
        ];
        pipeline.extensions[1].failure_policy = ExtensionFailurePolicyV1::Reject;
        let cancel = CancellationToken::new();
        assert!(matches!(
            transform_document(&pipeline, "default", &document("  "), &cancel),
            Err(ExtensionError::Rejected)
        ));
        pipeline.reverse_response = true;
        let item = transform_document(&pipeline, "default", &document("  "), &cancel)
            .unwrap()
            .unwrap();
        assert_eq!(item["title"], "");
    }
    #[test]
    fn unknown_label_and_cancel_do_not_fall_back() {
        let pipeline = ExtensionPipelineV1::default();
        let cancel = CancellationToken::new();
        assert!(matches!(
            transform_document(&pipeline, "missing", &document("x"), &cancel),
            Err(ExtensionError::UnknownRoute)
        ));
        cancel.cancel();
        assert!(matches!(
            transform_document(&pipeline, "default", &document("x"), &cancel),
            Err(ExtensionError::Cancelled)
        ));
    }
    #[test]
    fn finalization_runs_once_and_preserves_policy_denial() {
        let mut lifecycle = RequestLifecycle::new(&ExtensionPipelineV1::default()).unwrap();
        lifecycle.entered = vec!["first".into(), "second".into()];
        assert!(lifecycle.finalize(true));
        assert!(!lifecycle.finalize(false));
        assert!(lifecycle.policy_denied());
        assert_eq!(lifecycle.cleanup_order(), &["second", "first"]);
    }
    #[test]
    fn deadline_is_typed_without_sleep_or_network() {
        let started = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            guard(&CancellationToken::new(), started, 1),
            Err(ExtensionError::Deadline)
        ));
    }
}
