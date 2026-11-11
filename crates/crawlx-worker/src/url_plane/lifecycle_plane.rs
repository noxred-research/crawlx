//! Per-attempt extension lifecycle ownership and measured report facts.
//!
//! One [`crate::extensions::RequestLifecycle`] exists for every leased attempt, created before any
//! admission branch can finish the row. Every branch (static HTTP, cached, scrape engine, delegate,
//! browser publication) dispatches the boundaries it really executes and ends through one of the
//! sealing paths below, so exactly one terminal outcome is chosen per attempt:
//!
//! * a terminal row commit seals the lifecycle and carries its receipts and the attempt's
//!   measured report facts in the same fenced transaction ([`UrlPlaneRunner::seal_extensions`],
//!   [`UrlPlaneRunner::attempt_report_facts`]);
//! * a release that is not terminal (drain give-back, cooldown defer, rate-limit retry) persists
//!   the attempt's receipts under its still-live fence before the fence is released
//!   ([`UrlPlaneRunner::release_attempt`]).
//!
//! Policy denial is sticky: a callback can never turn a denial into success, and a status that
//! the lifecycle disagrees with is downgraded, never upgraded.

use super::*;
use crate::extensions::RequestLifecycle;
use crate::report_history::ReportStageTimer;
use crawlx_core::custody::CustodyLease;
use crawlx_core::extensions::{
    ExtensionError, ExtensionEventV1, ExtensionReasonV1, ExtensionReceiptV1, ExtensionResultV1,
    ExtensionTerminalV1,
};
use crawlx_core::report_history::{
    AlertCodeV1, AlertContextV1, AlertSeverityV1, PipelineStageV1, PipelineStateV1, ProcessorIdentityV1,
    ProcessorStageV1, ReportDataV1, ReportFactV1, StageOutcomeV1,
};

/// Leased rows that can hold a lifecycle at once. A plane never holds more than one batch.
pub(super) const MAX_ACTIVE_ATTEMPTS: usize = 64;
/// Processor schema revision stamped on every stage fact this plane measures.
const PROCESSOR_VERSION: u32 = 1;
/// Facts one terminal commit may carry from this producer (storage adds at most three itself).
const MAX_ATTEMPT_FACTS: usize = 60;

/// Why a lifecycle boundary ended its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LifecycleStop {
    /// Native policy denial; always wins.
    Denied,
    /// Caller cancellation.
    Cancelled,
    /// A compiled callback skipped the request.
    Skipped,
    /// A compiled callback or the bounded dispatcher failed the request.
    Failed,
}

/// Terminal facts of one sealed attempt.
pub(super) struct SealedAttempt {
    /// Receipts to commit, empty when the pipeline is not configured.
    pub receipts: Vec<ExtensionReceiptV1>,
    /// The immutable terminal outcome the lifecycle chose.
    pub terminal: Option<ExtensionTerminalV1>,
}

/// One leased attempt's lifecycle handle and measured evidence.
pub(super) struct ActiveAttempt {
    lifecycle: RequestLifecycle,
    url_key: Option<crawlx_core::hash::Digest>,
    wire: Option<ReportDataV1>,
    stages: Vec<ReportDataV1>,
    fetch: Option<PipelineStateV1>,
    parse: Option<PipelineStateV1>,
    dns: Vec<(crawlx_core::hash::Digest, ReportDataV1)>,
    dns_dropped: u64,
    response: Option<(u16, Option<u64>)>,
}

/// The terminal a row status requests. A lifecycle that already chose a worse terminal keeps it.
fn requested_terminal(status: FrontierStatus) -> ExtensionTerminalV1 {
    match status {
        FrontierStatus::Succeeded => ExtensionTerminalV1::Completed,
        FrontierStatus::Failed | FrontierStatus::Unreachable => {
            ExtensionTerminalV1::Failed(ExtensionReasonV1::Processing)
        }
        FrontierStatus::PolicyBlocked | FrontierStatus::RobotsBlocked => {
            ExtensionTerminalV1::Skipped(ExtensionReasonV1::PolicyDenied)
        }
        FrontierStatus::Abandoned | FrontierStatus::Pending | FrontierStatus::Leased => {
            ExtensionTerminalV1::Skipped(ExtensionReasonV1::Cancelled)
        }
    }
}

fn stop_of(result: Result<ExtensionResultV1, ExtensionError>) -> Option<LifecycleStop> {
    match result {
        Ok(ExtensionResultV1::Skip(ExtensionReasonV1::PolicyDenied)) | Err(ExtensionError::PolicyDenied) => {
            Some(LifecycleStop::Denied)
        }
        Ok(ExtensionResultV1::Skip(ExtensionReasonV1::Cancelled)) | Err(ExtensionError::Cancelled) => {
            Some(LifecycleStop::Cancelled)
        }
        Ok(ExtensionResultV1::Skip(_)) => Some(LifecycleStop::Skipped),
        Ok(ExtensionResultV1::Fail(_)) | Err(_) => Some(LifecycleStop::Failed),
        Ok(_) => None,
    }
}

fn state_of(outcome: StageOutcomeV1) -> PipelineStateV1 {
    match outcome {
        StageOutcomeV1::Succeeded => PipelineStateV1::Succeeded,
        StageOutcomeV1::Failed => PipelineStateV1::Failed,
        _ => PipelineStateV1::Skipped,
    }
}

impl UrlPlaneRunner {
    /// Create this attempt's lifecycle. A stale handle for the same row is dropped first.
    ///
    /// # Errors
    /// Fails when the pipeline cannot be configured or too many attempts are live.
    pub(super) fn begin_attempt(&self, id: i64) -> Result<RequestLifecycle, WorkerError> {
        let lifecycle = RequestLifecycle::new(&self.crawl.extensions)
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        let mut attempts = self.attempts.lock();
        if !attempts.contains_key(&id) && attempts.len() >= MAX_ACTIVE_ATTEMPTS {
            return Err(WorkerError::Config("too many active extension lifecycles".into()));
        }
        attempts.insert(
            id,
            ActiveAttempt {
                lifecycle: lifecycle.clone(),
                url_key: None,
                wire: None,
                stages: Vec::new(),
                fetch: None,
                parse: None,
                dns: Vec::new(),
                dns_dropped: 0,
                response: None,
            },
        );
        Ok(lifecycle)
    }

    /// The shared handle of a live attempt.
    pub(super) fn attempt_lifecycle(&self, id: i64) -> Option<RequestLifecycle> {
        self.attempts
            .lock()
            .get(&id)
            .map(|attempt| attempt.lifecycle.clone())
    }

    /// Forget an attempt. Dropping the last unsealed handle finalizes it as cancelled.
    pub(super) fn end_attempt(&self, id: i64) {
        let removed = self.attempts.lock().remove(&id);
        drop(removed);
    }

    /// Record the opaque request identity that scopes this attempt's report facts.
    pub(super) fn note_url_key(&self, id: i64, key: crawlx_core::hash::Digest) {
        if let Some(attempt) = self.attempts.lock().get_mut(&id) {
            attempt.url_key = Some(key);
        }
    }

    /// Record the measured outcome of one processor stage.
    pub(super) fn note_stage(
        &self,
        id: i64,
        timer: &ReportStageTimer,
        stage: ProcessorStageV1,
        outcome: StageOutcomeV1,
        processor: ProcessorIdentityV1,
    ) {
        let Ok(data) = timer.finish(stage, outcome, processor, PROCESSOR_VERSION) else {
            return;
        };
        if let Some(attempt) = self.attempts.lock().get_mut(&id) {
            match stage {
                ProcessorStageV1::Fetch => attempt.fetch = Some(state_of(outcome)),
                ProcessorStageV1::Parse => attempt.parse = Some(state_of(outcome)),
                _ => {}
            }
            attempt.stages.push(data);
        }
    }

    /// Record the resolver's own observations, including failed lookups, for this attempt. They
    /// replace any final-only DNS inference. Loss at the capture bound stays an exact count.
    pub(super) fn note_dns(&self, id: i64, batch: crawlx_fetch::resolver::DnsReportBatchV1) {
        if let Some(attempt) = self.attempts.lock().get_mut(&id) {
            attempt
                .dns
                .extend(batch.observations.into_iter().map(|o| (o.host_key, o.data)));
            attempt.dns_dropped = attempt.dns_dropped.saturating_add(batch.dropped);
            attempt.dns.truncate(MAX_ATTEMPT_FACTS / 2);
        }
    }

    /// Record independently measured wire evidence. Only an observed byte count is reported;
    /// the decoded body length is never substituted.
    pub(super) fn note_wire(&self, id: i64, response: &FetchResponse) {
        let duration_us = u64::try_from(response.duration.as_micros()).ok();
        let retry_after_ms = response
            .headers
            .get(http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .and_then(|seconds| seconds.checked_mul(1000));
        if let Some(attempt) = self.attempts.lock().get_mut(&id) {
            attempt.response = Some((response.status.as_u16(), retry_after_ms));
            if response.wire_bytes.is_some() || duration_us.is_some() {
                attempt.wire = Some(ReportDataV1::Wire {
                    received_bytes: response.wire_bytes,
                    sent_bytes: None,
                    duration_us,
                });
            }
        }
    }

    /// The final response status and Retry-After of this attempt, when it reached the network.
    pub(super) fn attempt_response(&self, id: i64) -> Option<(u16, Option<u64>)> {
        self.attempts.lock().get(&id).and_then(|attempt| attempt.response)
    }

    /// The token a lifecycle boundary observes. A graceful drain lets the response in hand finish,
    /// so only the hard caller cancellation interrupts a dispatch then.
    pub(super) fn event_cancel(&self, cancel: &CancellationToken) -> CancellationToken {
        if self.shutdown_checkpoint_requested() {
            self.hard_cancel.clone().unwrap_or_default()
        } else {
            cancel.clone()
        }
    }

    /// Dispatch one real boundary. `Some` means the request must end now.
    pub(super) fn dispatch(
        &self,
        id: i64,
        event: ExtensionEventV1,
        cancel: &CancellationToken,
    ) -> Option<LifecycleStop> {
        let mut lifecycle = self.attempt_lifecycle(id)?;
        let token = self.event_cancel(cancel);
        stop_of(lifecycle.dispatch(event, &token))
    }

    /// Dispatch several real boundaries in order, stopping at the first refusal.
    pub(super) fn dispatch_many<const N: usize>(
        &self,
        id: i64,
        events: [ExtensionEventV1; N],
        cancel: &CancellationToken,
    ) -> Option<LifecycleStop> {
        events
            .into_iter()
            .find_map(|event| self.dispatch(id, event, cancel))
    }

    /// End a request a lifecycle boundary stopped, through the ordinary terminal paths.
    ///
    /// # Errors
    /// Returns the terminal commit's storage failure.
    pub(super) async fn stop_request(
        &self,
        entry: &FrontierEntry,
        stop: LifecycleStop,
    ) -> Result<(), WorkerError> {
        match stop {
            LifecycleStop::Denied => {
                self.finish(
                    entry,
                    FrontierStatus::PolicyBlocked,
                    Some("extension_policy_denied".into()),
                )
                .await
            }
            LifecycleStop::Cancelled => {
                self.finish(
                    entry,
                    FrontierStatus::Abandoned,
                    Some("acquisition_cancelled".to_owned()),
                )
                .await?;
                self.counters
                    .attempt_with_reason(Plane::Urls, Attempt::Abandoned, "acquisition_cancelled");
                Ok(())
            }
            LifecycleStop::Skipped => {
                self.fail(
                    entry,
                    "extension_skipped",
                    "extension_skipped",
                    Attempt::Failed,
                    serde_json::json!({"reason":"extension_skipped"}),
                )
                .await
            }
            LifecycleStop::Failed => {
                self.fail(
                    entry,
                    "extension_failed",
                    "extension_failed",
                    Attempt::Failed,
                    serde_json::json!({"reason":"extension_failed"}),
                )
                .await
            }
        }
    }

    /// Finish the lifecycle for a terminal commit and snapshot its receipts.
    ///
    /// The snapshot, not a drain, so a retried commit carries the identical receipts.
    ///
    /// # Errors
    /// Fails when bounded receipt accounting cannot complete.
    pub(super) fn seal_extensions(
        &self,
        id: i64,
        status: FrontierStatus,
    ) -> Result<SealedAttempt, WorkerError> {
        let Some(mut lifecycle) = self.attempt_lifecycle(id) else {
            return Ok(SealedAttempt {
                receipts: Vec::new(),
                terminal: None,
            });
        };
        lifecycle.finish(requested_terminal(status)).map_err(|error| {
            WorkerError::Config(format!("extension lifecycle finalization failed: {error}"))
        })?;
        let receipts = if self.crawl.extensions.configured() {
            lifecycle.events()
        } else {
            Vec::new()
        };
        Ok(SealedAttempt {
            receipts,
            terminal: lifecycle.terminal(),
        })
    }

    /// Persist this attempt's receipts under its live fence, then forget it. Call before every
    /// non-terminal release (`give_back`, `defer_fenced`, `retry_fenced`).
    ///
    /// # Errors
    /// Returns `LeaseLost` when the fence is gone, or the repository failure.
    pub(super) async fn release_attempt(
        &self,
        entry: &FrontierEntry,
        terminal: ExtensionTerminalV1,
    ) -> Result<(), WorkerError> {
        let Some(mut lifecycle) = self.attempt_lifecycle(entry.id) else {
            return Ok(());
        };
        lifecycle.finish(terminal).map_err(|error| {
            WorkerError::Config(format!("extension lifecycle finalization failed: {error}"))
        })?;
        if self.crawl.extensions.configured() {
            let fence = self
                .held
                .lock()
                .get(&entry.id)
                .copied()
                .ok_or(StoreError::LeaseLost)?;
            let receipts = lifecycle.events();
            self.deps
                .request_commits
                .record_extension_attempt(self.run, entry.id, fence, u32::from(entry.attempts), &receipts)
                .await?;
        }
        self.end_attempt(entry.id);
        Ok(())
    }

    /// Measured facts of this attempt for its terminal commit. Nothing is invented: wire facts
    /// exist only for an observed response, stage durations only for a stage that ran, and a
    /// parse checkpoint only after a parse actually ran. Index and completion checkpoints belong to
    /// the storage commit (pending while delivery is queued), never to this producer.
    ///
    /// # Errors
    /// Returns the run lookup or fact-identity failure.
    pub(super) async fn attempt_report_facts(
        &self,
        entry: &FrontierEntry,
        fence: i64,
        status: FrontierStatus,
    ) -> Result<Vec<ReportFactV1>, WorkerError> {
        let (url_key, wire, stages, fetch, parse, dns, dns_dropped) = {
            let attempts = self.attempts.lock();
            let Some(attempt) = attempts.get(&entry.id) else {
                return Ok(Vec::new());
            };
            (
                attempt.url_key,
                attempt.wire.clone(),
                attempt.stages.clone(),
                attempt.fetch,
                attempt.parse,
                attempt.dns.clone(),
                attempt.dns_dropped,
            )
        };
        let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
        let lease = CustodyLease::for_url(tenant, self.run, entry.id, self.worker, fence);
        let at = self.deps.clock.now();
        let attempt_no = entry.attempts.max(1);
        let mut data: Vec<(String, ReportDataV1)> = Vec::new();
        if let Some(state) = fetch {
            data.push((
                "pipeline_fetch".into(),
                ReportDataV1::Pipeline {
                    stage: PipelineStageV1::Fetch,
                    state,
                },
            ));
        }
        // every fact of the attempt joins the requested host; a DNS fact keeps the host it resolved
        let page_host = entry
            .url
            .url
            .host_str()
            .map(crawlx_core::report_history::report_host_key);
        let mut hosts: std::collections::BTreeMap<String, crawlx_core::hash::Digest> =
            std::collections::BTreeMap::new();
        for (ordinal, (host_key, observed)) in dns.into_iter().enumerate() {
            let label = format!("dns_{ordinal}");
            hosts.insert(label.clone(), host_key);
            data.push((label, observed));
        }
        if dns_dropped != 0 {
            data.push(("dns_loss".into(), ReportDataV1::Loss { dropped: dns_dropped }));
        }
        if let Some(wire) = wire {
            data.push(("wire".into(), wire));
        }
        for (ordinal, stage) in stages.into_iter().enumerate() {
            data.push((format!("stage_{ordinal}"), stage));
        }
        if let Some(state) = parse {
            data.push((
                "pipeline_parse".into(),
                ReportDataV1::Pipeline {
                    stage: PipelineStageV1::Parse,
                    state,
                },
            ));
        }
        match status {
            FrontierStatus::Failed | FrontierStatus::Unreachable => data.push((
                "alert".into(),
                ReportDataV1::Alert {
                    severity: AlertSeverityV1::Error,
                    code: AlertCodeV1::ProcessorFailure,
                    context: AlertContextV1::Processing,
                },
            )),
            FrontierStatus::Abandoned => data.push((
                "alert".into(),
                ReportDataV1::Alert {
                    severity: AlertSeverityV1::Warning,
                    code: AlertCodeV1::Cancelled,
                    context: AlertContextV1::Processing,
                },
            )),
            _ => {}
        }
        data.truncate(MAX_ATTEMPT_FACTS);
        let mut facts = Vec::with_capacity(data.len());
        for (label, payload) in data {
            let encoded = serde_json::to_vec(&(tenant, self.run, entry.id, fence, attempt_no, &label))
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            let id = crawlx_core::hash::Digest::of("crawlx/report-attempt/v1", &encoded);
            let mut fact = ReportFactV1::new(&lease, id, at, payload);
            fact.request_id = Some(entry.id);
            fact.url_key = url_key;
            fact.host_key = hosts.get(&label).copied().or(page_host);
            fact.attempt = attempt_no;
            fact.validate()?;
            facts.push(fact);
        }
        Ok(facts)
    }
}
