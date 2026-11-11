//! Bounded browser evidence projections. Body bytes remain in policy-owned artifacts.

use crate::ids::ArtifactRef;
use crate::traffic::TrafficEvent;
use serde::{Deserialize, Serialize};

/// Browser evidence captured at an observation boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BrowserProjection {
    /// Capture plane producing this projection; currently `cdp`, not a proxy claim.
    pub capture_source: String,
    /// Initial service-worker script requests precede target attachment and are unavailable.
    pub service_worker_bootstrap: CaptureAvailability,
    /// URL-filtered XHR/Fetch responses; absent when capture is disabled.
    pub xhr: Option<NetworkProjection>,
    /// Network and console diagnostics; absent when diagnostics are disabled.
    pub diagnostics: Option<BrowserDiagnostics>,
}

impl Default for BrowserProjection {
    fn default() -> Self {
        Self {
            capture_source: "cdp".to_owned(),
            service_worker_bootstrap: CaptureAvailability::UnavailableBeforeTargetAttachment,
            xhr: None,
            diagnostics: None,
        }
    }
}

/// Availability of evidence that CDP target attachment cannot observe retroactively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum CaptureAvailability {
    /// The initial service-worker script request occurred before its CDP target attached.
    UnavailableBeforeTargetAttachment,
}

/// One already-redacted browser response, without inline body bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BrowserResponse {
    /// Original context traffic sequence, not a projection-local counter.
    pub seq: u64,
    /// Redacted main-document URL, when supplied by the browser capture source.
    pub page_url: Option<String>,
    /// Browser resource type, such as `xhr` or `fetch`.
    pub resource_type: Option<String>,
    /// HTTP request method.
    pub method: String,
    /// Already-redacted request URL.
    pub url: String,
    /// Actual response status; absent if no response arrived.
    pub status: Option<u16>,
    /// Redacted request headers, retaining browser provenance tags.
    pub request_headers: Vec<(String, String)>,
    /// Redacted response headers, retaining body-state and byte-count metadata.
    pub response_headers: Vec<(String, String)>,
    /// Policy-approved retained response body, never invented for denied bodies.
    pub response_body: Option<ArtifactRef>,
    /// Capture source's body state; absence does not imply an empty body.
    pub body_state: Option<String>,
}

impl From<TrafficEvent> for BrowserResponse {
    fn from(event: TrafficEvent) -> Self {
        let request_tag = |name: &str| {
            event
                .request_headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let page_url = request_tag("x-crawlx-page-url");
        let resource_type = request_tag("x-crawlx-resource-type");
        let body_state = event
            .response_headers
            .iter()
            .find(|(name, _)| name == "x-crawlx-body-state")
            .map(|(_, value)| value.clone());
        Self {
            seq: event.seq,
            page_url,
            resource_type,
            method: event.method,
            url: event.url,
            status: event.status,
            request_headers: event.request_headers,
            response_headers: event.response_headers,
            response_body: event.response_body,
            body_state,
        }
    }
}

/// Ordered bounded response metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkProjection {
    /// Retained responses in original capture order.
    pub records: Vec<BrowserResponse>,
    /// Records removed by count or serialized metadata byte bounds.
    /// Oversized tagged XHR/Fetch candidates count without scanning unretainable URLs against patterns.
    pub dropped_records: u64,
    /// Some eligible evidence could not be retained.
    pub truncated: bool,
    /// Sum of serialized JSON record bytes, excluding the projection envelope.
    pub metadata_bytes: u64,
}

/// Whether a console was observed rather than merely returning an empty list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ConsoleAvailability {
    /// Console collection was enabled for this browser profile.
    Available,
    /// Caller disabled console collection.
    #[default]
    Disabled,
    /// Stealth profile does not enable console instrumentation.
    Stealth,
}

/// Bounded redacted console evidence with explicit availability.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ConsoleProjection {
    /// Why console evidence is or is not available.
    pub availability: ConsoleAvailability,
    /// Redacted messages, in browser order, each limited to 4096 UTF-8 bytes.
    pub messages: Vec<String>,
    /// Messages excluded by count or total serialized-byte bounds.
    pub dropped_messages: u64,
    /// Messages were dropped or shortened at a UTF-8 boundary.
    pub truncated: bool,
    /// Sum of serialized JSON string bytes, excluding the projection envelope.
    pub metadata_bytes: u64,
}

/// Network and console evidence sharing total record-count and serialized metadata byte budgets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BrowserDiagnostics {
    /// Bounded network events in original sequence, consuming the shared count and byte budgets first.
    pub network: NetworkProjection,
    /// Explicitly available, disabled, or stealth-unavailable console collection.
    pub console: ConsoleProjection,
}
