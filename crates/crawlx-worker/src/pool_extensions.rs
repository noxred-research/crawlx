//! Typed browser lifecycle hooks for [`crate::pool::BrowserPool`].
//!
//! A pool clone carrying [`PoolExtensions`] executes the reviewed native pipeline at the
//! exact points where the pool performs a real effect: before and after a process it owns
//! is launched, before a context (page) is created, and after a context closure is
//! confirmed. A reused or attached backend is never reported as a launch. Hooks receive
//! closed metadata only; there is no callback registry, raw browser handle or pool
//! reference, so a hook can neither close the pool nor widen any authority.
//!
//! Every acquisition is one lifecycle attempt. Its ordered receipts are persisted through
//! the run's existing event log, stamped with the session binding generation and fence.
//! A refusal (`Skip`/`Fail` result, policy denial, cancellation, capacity) is sticky for the
//! attempt and stops the effect it guards.

use crate::extensions::RequestLifecycle;
use crawlx_core::extensions::{
    ExtensionError, ExtensionEventV1, ExtensionPipelineV1, ExtensionReasonV1, ExtensionResultV1,
    ExtensionTerminalV1,
};
use crawlx_core::repo::EventRepo;
use crawlx_core::{BrowserError, ContextConfig, CrawlRunId, SessionId};
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Event kind of every persisted browser lifecycle receipt.
pub const BROWSER_EVENT_KIND: &str = "extension.browser";

/// Detached receipt writers allowed at once after a cancelled acquisition.
const MAX_PENDING_FLUSHES: usize = 16;

/// Per-run authority to run browser lifecycle hooks and persist their receipts.
#[derive(Clone)]
#[non_exhaustive]
pub struct PoolExtensions {
    pipeline: Arc<ExtensionPipelineV1>,
    events: Arc<dyn EventRepo>,
    run: CrawlRunId,
    cancel: CancellationToken,
    flushes: Arc<Mutex<JoinSet<()>>>,
}

impl std::fmt::Debug for PoolExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolExtensions")
            .field("run", &self.run)
            .finish_non_exhaustive()
    }
}

impl PoolExtensions {
    /// Bind one run's immutable pipeline, event log and cancellation authority.
    ///
    /// # Errors
    /// Rejects an invalid pipeline before any browser is allocated.
    pub fn new(
        pipeline: &ExtensionPipelineV1,
        events: Arc<dyn EventRepo>,
        run: CrawlRunId,
        cancel: CancellationToken,
    ) -> Result<Self, ExtensionError> {
        pipeline.validate()?;
        Ok(Self {
            pipeline: Arc::new(pipeline.clone()),
            events,
            run,
            cancel,
            flushes: Arc::new(Mutex::new(JoinSet::new())),
        })
    }

    /// Start one acquisition attempt. `None` keeps an unconfigured pipeline on the legacy path.
    pub(crate) fn attempt(&self, config: &ContextConfig) -> Result<Option<BrowserAttempt>, BrowserError> {
        if !self.pipeline.configured() {
            return Ok(None);
        }
        let lifecycle = RequestLifecycle::new(&self.pipeline).map_err(refusal)?;
        Ok(Some(BrowserAttempt {
            lifecycle,
            ext: self.clone(),
            session: config.session_id,
            stamp: config
                .session_binding
                .as_ref()
                .map(|binding| (binding.generation, binding.lease_fence, binding.state_version)),
        }))
    }
}

/// Content-free refusal; the typed cause stays in the persisted receipts.
fn refusal(error: ExtensionError) -> BrowserError {
    let code = match error {
        ExtensionError::PolicyDenied => "policy_denied",
        ExtensionError::Cancelled => "cancelled",
        ExtensionError::Limit => "capacity",
        ExtensionError::Rejected => "rejected",
        _ => "failed",
    };
    BrowserError::Unsupported(format!("extension_refused: {code}"))
}

/// One browser acquisition's ordered lifecycle, owned by the acquirer and then its lease.
pub(crate) struct BrowserAttempt {
    lifecycle: RequestLifecycle,
    ext: PoolExtensions,
    session: SessionId,
    /// Binding generation, lease fence and state version at acquisition.
    stamp: Option<(u64, i64, u64)>,
}

impl BrowserAttempt {
    /// Dispatch one boundary; a `Skip`/`Fail` result or any dispatcher refusal stops the effect.
    pub(crate) fn dispatch(&mut self, event: ExtensionEventV1) -> Result<(), BrowserError> {
        match self.lifecycle.dispatch(event, &self.ext.cancel) {
            Ok(ExtensionResultV1::Skip(_) | ExtensionResultV1::Fail(_)) => {
                Err(refusal(ExtensionError::Rejected))
            }
            Ok(_) => Ok(()),
            Err(error) => Err(refusal(error)),
        }
    }

    /// Record a boundary that already happened. Refusal cannot undo it, but stays sticky in the
    /// terminal outcome.
    pub(crate) fn observe(&mut self, event: ExtensionEventV1) {
        let _ = self.lifecycle.dispatch(event, &self.ext.cancel);
    }

    fn payload(&self, receipt: &crawlx_core::extensions::ExtensionReceiptV1) -> serde_json::Value {
        serde_json::json!({
            "scope": "browser",
            "session_id": self.session.0,
            "generation": self.stamp.map(|s| s.0),
            "fence": self.stamp.map(|s| s.1),
            "stateVersion": self.stamp.map(|s| s.2),
            "receipt": receipt,
        })
    }

    /// Persist undrained receipts in order. Persistence failure never changes the effect.
    pub(crate) async fn flush(&mut self) {
        for receipt in self.lifecycle.drain_events() {
            let payload = self.payload(&receipt);
            if let Err(error) = self
                .ext
                .events
                .append(self.ext.run, BROWSER_EVENT_KIND, payload)
                .await
            {
                tracing::warn!(%error, "browser lifecycle receipt not recorded");
            }
        }
    }

    /// Seal with the actual outcome, then persist the ordered trail once.
    pub(crate) async fn finish(&mut self, outcome: ExtensionTerminalV1) {
        if let Err(error) = self.lifecycle.finish(outcome) {
            tracing::warn!(%error, "browser lifecycle seal refused");
        }
        self.flush().await;
    }

    /// Terminal outcome for a failed effect: cancellation is a skip, everything else a failure.
    pub(crate) fn failure_outcome(&self) -> ExtensionTerminalV1 {
        if self.ext.cancel.is_cancelled() {
            ExtensionTerminalV1::Skipped(ExtensionReasonV1::Cancelled)
        } else {
            ExtensionTerminalV1::Failed(ExtensionReasonV1::Processing)
        }
    }
}

impl Drop for BrowserAttempt {
    fn drop(&mut self) {
        // A dropped acquisition or unreleased lease has no async epilogue. Seal as cancelled and
        // hand the already-bounded receipts to a bounded owned writer.
        let _ = self
            .lifecycle
            .finish(ExtensionTerminalV1::Skipped(ExtensionReasonV1::Cancelled));
        let receipts = self.lifecycle.drain_events();
        if receipts.is_empty() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let payloads: Vec<_> = receipts.iter().map(|receipt| self.payload(receipt)).collect();
        let events = Arc::clone(&self.ext.events);
        let run = self.ext.run;
        let mut flushes = self.ext.flushes.lock();
        while flushes.try_join_next().is_some() {}
        if flushes.len() >= MAX_PENDING_FLUSHES {
            tracing::warn!("browser lifecycle receipts dropped: writer capacity exhausted");
            return;
        }
        flushes.spawn_on(
            async move {
                for payload in payloads {
                    if let Err(error) = events.append(run, BROWSER_EVENT_KIND, payload).await {
                        tracing::warn!(%error, "browser lifecycle receipt not recorded");
                    }
                }
            },
            &runtime,
        );
    }
}
