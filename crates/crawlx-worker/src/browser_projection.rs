//! Opt-in browser evidence emitted through the ordinary run event repository.

use crate::actor::SessionHandle;
use crate::error::WorkerError;
use crate::run::RunContext;
use crawlx_core::browser::BrowserError;
use crawlx_core::error::StoreError;
use crawlx_core::observation::ObservationBundle;
use crawlx_core::page_op::{PageOp, PageOpResult};
use serde::Serialize;

/// Capture bounded evidence for an actual observation; disabled capture has no browser effect.
pub(crate) async fn observe(
    handle: &SessionHandle,
    rc: &RunContext,
    bundle: &ObservationBundle,
) -> Result<(), WorkerError> {
    let config = &rc.crawl.capture.browser;
    if config.xhr.is_none() && config.diagnostics.is_none() {
        return Ok(());
    }
    let PageOpResult::Projection(projection) = handle.page_op(PageOp::CaptureProjection).await? else {
        return Err(BrowserError::Unsupported("browser returned a non-projection result".into()).into());
    };
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Event<'a> {
        session_id: crawlx_core::SessionId,
        observation_seq: u64,
        projection: &'a crawlx_core::browser_projection::BrowserProjection,
    }
    let payload = serde_json::to_value(Event {
        session_id: bundle.session_id,
        observation_seq: bundle.seq,
        projection: &projection,
    })
    .map_err(|error| StoreError::Serialization(error.to_string()))?;
    rc.stores
        .events
        .append(rc.run, "browser.projection", payload)
        .await?;
    Ok(())
}
