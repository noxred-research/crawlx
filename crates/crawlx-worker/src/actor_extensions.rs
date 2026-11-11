//! Browser-boundary lifecycle execution for the Session Actor.
//!
//! The actor is the only code that calls a `BrowserContext`, so it alone reports the
//! pre/post-navigation boundaries. Hooks receive closed metadata; there is no raw handle,
//! callback or evaluation surface. A `Skip`/`Fail` result stops the guarded step, a policy
//! denial is sticky, and every ordered receipt is appended to the run event log stamped with
//! the live binding generation and fence and the observation epoch.

use super::SessionActor;
use crate::error::SessionError;
use crate::extensions::RequestLifecycle;
use crate::pool::BROWSER_EVENT_KIND;
use crawlx_core::extensions::{
    ExtensionError, ExtensionEventV1, ExtensionReasonV1, ExtensionReceiptV1, ExtensionResultV1,
    ExtensionTerminalV1,
};
use crawlx_core::StoreError;

/// Owner handed to `Bytes::from_owner`: it keeps the producer's admitted text (and therefore
/// its true byte reservation) alive for as long as any `Bytes` view or clone exists.
pub(super) struct AdmittedHtml(pub(super) crawlx_core::parser_memory::AdmittedText);

impl AsRef<[u8]> for AdmittedHtml {
    fn as_ref(&self) -> &[u8] {
        self.0.as_str().as_bytes()
    }
}

/// Typed refusal carried by a callback result, if any. `Continue` and annotations proceed.
pub(super) fn refusal(result: &ExtensionResultV1) -> Option<ExtensionError> {
    match result {
        ExtensionResultV1::Skip(ExtensionReasonV1::PolicyDenied) => Some(ExtensionError::PolicyDenied),
        ExtensionResultV1::Skip(ExtensionReasonV1::Cancelled) => Some(ExtensionError::Cancelled),
        ExtensionResultV1::Skip(ExtensionReasonV1::Capacity)
        | ExtensionResultV1::Fail(ExtensionReasonV1::Capacity) => Some(ExtensionError::Limit),
        ExtensionResultV1::Skip(_) => Some(ExtensionError::Rejected),
        ExtensionResultV1::Fail(_) => Some(ExtensionError::Failed),
        _ => None,
    }
}

/// Immutable terminal outcome that describes how an actor operation actually ended.
pub(super) fn terminal_for<T>(result: &Result<T, SessionError>) -> ExtensionTerminalV1 {
    match result {
        Ok(_) => ExtensionTerminalV1::Completed,
        Err(SessionError::Cancelled | SessionError::Extension(ExtensionError::Cancelled)) => {
            ExtensionTerminalV1::Skipped(ExtensionReasonV1::Cancelled)
        }
        Err(SessionError::Extension(ExtensionError::PolicyDenied)) => {
            ExtensionTerminalV1::Skipped(ExtensionReasonV1::PolicyDenied)
        }
        Err(SessionError::Extension(ExtensionError::Rejected)) => {
            ExtensionTerminalV1::Skipped(ExtensionReasonV1::Rejected)
        }
        Err(SessionError::Extension(ExtensionError::Limit)) => {
            ExtensionTerminalV1::Failed(ExtensionReasonV1::Capacity)
        }
        Err(SessionError::Extension(_)) => ExtensionTerminalV1::Failed(ExtensionReasonV1::HandlerFailed),
        Err(_) => ExtensionTerminalV1::Failed(ExtensionReasonV1::Processing),
    }
}

impl SessionActor {
    /// Dispatch one browser boundary. The caller stops on any refusal.
    ///
    /// # Errors
    /// Policy denial, cancellation, capacity, rejection or callback failure.
    pub(super) fn browser_boundary(
        &self,
        chain: &mut RequestLifecycle,
        event: ExtensionEventV1,
    ) -> Result<(), SessionError> {
        let result = chain.dispatch(event, &self.cfg.origin_cancel)?;
        match refusal(&result) {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    /// Seal `chain` with the operation's actual outcome and persist its ordered trail.
    /// Persistence is best effort, like every actor audit row; it never changes the outcome.
    pub(super) async fn finish_lifecycle(
        &mut self,
        scope: &'static str,
        mut chain: RequestLifecycle,
        outcome: ExtensionTerminalV1,
    ) {
        if let Err(error) = chain.finish(outcome) {
            tracing::warn!(%error, scope, "extension lifecycle seal refused");
        }
        let receipts = chain.drain_events();
        self.audit_extension_receipts(scope, receipts).await;
    }

    /// Dispatch one item-path boundary. `Ok(false)` is a typed skip of this document or item.
    ///
    /// # Errors
    /// Cancellation, capacity, callback failure or dispatcher refusal.
    pub(super) fn item_boundary(
        &self,
        chain: Option<&mut RequestLifecycle>,
        event: ExtensionEventV1,
    ) -> Result<bool, StoreError> {
        let Some(chain) = chain else {
            return Ok(true);
        };
        let result = chain
            .dispatch(event, &self.cfg.origin_cancel)
            .map_err(|_| StoreError::Conflict("extension lifecycle refused".into()))?;
        match result {
            ExtensionResultV1::Skip(ExtensionReasonV1::Cancelled) | ExtensionResultV1::Fail(_) => {
                Err(StoreError::Conflict("extension lifecycle failed".into()))
            }
            ExtensionResultV1::Skip(_) => Ok(false),
            _ => Ok(true),
        }
    }

    /// Append receipts in order under the current generation, fence and epoch.
    pub(super) async fn audit_extension_receipts(
        &mut self,
        scope: &'static str,
        receipts: Vec<ExtensionReceiptV1>,
    ) {
        if receipts.is_empty() {
            return;
        }
        let epoch = self.ctx.current_epoch();
        let (generation, fence) = self
            .cfg
            .context
            .session_binding
            .as_ref()
            .map_or((None, None), |binding| {
                (Some(binding.generation), Some(binding.lease_fence))
            });
        for receipt in receipts {
            self.audit(
                BROWSER_EVENT_KIND,
                serde_json::json!({
                    "scope": scope,
                    "generation": generation,
                    "fence": fence,
                    "epoch": {
                        "navigation": epoch.navigation_seq,
                        "document": epoch.document_seq,
                        "mutation": epoch.mutation_seq,
                    },
                    "receipt": receipt,
                }),
            )
            .await;
        }
    }
}
