//! Scripted `BrowserContext` for this crate's tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::bundle::testutil::bundle;
use async_trait::async_trait;
use crawlx_core::action::BrowserAction;
use crawlx_core::browser::{BrowserContext, BrowserError};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{
    ActionReceipt, NavigationResult, ObservationBundle, ObservationSpec, QuiescencePolicy, Revalidation,
    RuntimeLocator, SettleReport,
};
use crawlx_core::traffic::TrafficEvent;
use crawlx_core::CanonicalUrl;
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Default)]
pub struct ScriptedContext {
    /// Bundles handed out by `observe`, front first; a plain empty bundle when exhausted.
    pub bundles: VecDeque<ObservationBundle>,
    pub observes: u32,
    pub settles: u32,
    pub last_spec: Option<ObservationSpec>,
    pub fail_observe: bool,
    pub delay_ms: u64,
    pub settle_report: SettleReport,
}

impl ScriptedContext {
    pub fn new() -> Self {
        Self::default()
    }
}

fn unsupported<T>() -> Result<T, BrowserError> {
    Err(BrowserError::Unsupported("scripted context".to_owned()))
}

#[async_trait]
impl BrowserContext for ScriptedContext {
    async fn navigate(&mut self, _url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        unsupported()
    }

    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        self.observes += 1;
        self.last_spec = Some(spec);
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        if self.fail_observe {
            self.observes -= 1;
            return Err(BrowserError::TargetCrashed);
        }
        Ok(self
            .bundles
            .pop_front()
            .unwrap_or_else(|| bundle("https://example.com/")))
    }

    async fn revalidate(
        &mut self,
        _locator: &RuntimeLocator,
        _expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        unsupported()
    }

    async fn perform(&mut self, _action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        unsupported()
    }

    async fn settle(&mut self, _policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        self.settles += 1;
        Ok(self.settle_report.clone())
    }

    fn current_epoch(&self) -> ObservationEpoch {
        ObservationEpoch::default()
    }

    fn drain_traffic(&mut self) -> Vec<TrafficEvent> {
        Vec::new()
    }

    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError> {
        unsupported()
    }

    async fn import_storage(&mut self, _blob: &[u8]) -> Result<(), BrowserError> {
        unsupported()
    }

    async fn close(self: Box<Self>) -> Result<(), BrowserError> {
        Ok(())
    }
}
