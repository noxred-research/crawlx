//! Trust lanes and input fidelity.

use serde::{Deserialize, Serialize};

/// How an action reached the page.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    /// Real pointer events dispatched through CDP input (clicks, hover, drag, wheel).
    NativePointer,
    /// Real key events dispatched through CDP input (key presses, keyboard activation).
    NativeKeyboard,
    /// Real text input dispatched through CDP input.
    NativeTextInput,
    /// `DOM.setFileInputFiles`; diagnostic because no user gesture was involved.
    FileChooser,
    /// `Page.navigate`, tab switches: not a user gesture on a control.
    ScriptedNavigation,
    /// `HTMLElement.click()` and friends (not-trusted events).
    SyntheticDomEvent,
    /// A forced scroll (`DOM.scrollIntoViewIfNeeded`) brought the target into view because
    /// wheel input could not; diagnostic because the scroll was scripted.
    ScriptedScroll,
    /// Direct HTTP from the fetch plane (no browser).
    FetchPlane,
}

impl Fidelity {
    /// The lane an action with this fidelity belongs to.
    #[must_use]
    pub const fn lane(self) -> TrustLane {
        match self {
            Self::NativePointer | Self::NativeKeyboard | Self::NativeTextInput => TrustLane::TrustedUi,
            Self::FileChooser
            | Self::ScriptedNavigation
            | Self::ScriptedScroll
            | Self::SyntheticDomEvent
            | Self::FetchPlane => TrustLane::Diagnostic,
        }
    }

    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativePointer => "native_pointer",
            Self::NativeKeyboard => "native_keyboard",
            Self::NativeTextInput => "native_text_input",
            Self::FileChooser => "file_chooser",
            Self::ScriptedNavigation => "scripted_navigation",
            Self::ScriptedScroll => "scripted_scroll",
            Self::SyntheticDomEvent => "synthetic_dom_event",
            Self::FetchPlane => "fetch_plane",
        }
    }
}

/// Stored column on `actions` and `network_epochs`, never a post-hoc filter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TrustLane {
    /// Produced by real user-like input (native pointer, keyboard or text input).
    TrustedUi,
    /// Produced by scripted, synthetic or non-browser means; kept for diagnosis, not trusted as UI evidence.
    Diagnostic,
}

impl TrustLane {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedUi => "trusted_ui",
            Self::Diagnostic => "diagnostic",
        }
    }
}

impl std::str::FromStr for TrustLane {
    type Err = crate::error::CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trusted_ui" => Ok(Self::TrustedUi),
            "diagnostic" => Ok(Self::Diagnostic),
            other => Err(crate::error::CoreError::UnknownEnum {
                kind: "TrustLane",
                value: other.to_owned(),
            }),
        }
    }
}

/// Origin of a captured request.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TrafficOrigin {
    /// Requested by the page itself (document, scripts, XHR/fetch, images).
    Page,
    /// Requested by a service worker.
    ServiceWorker,
    /// WebSocket connection opened by the page.
    WebSocket,
    /// Server-sent events (`EventSource`) stream opened by the page.
    EventSource,
    /// Requested directly by the fetch plane, without a browser.
    FetchPlane,
}

/// Why a captured request has no network epoch (trail rule: a `NULL`
/// epoch needs an explicit reason, or `attribution = 'not_applicable'`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UnattributedReason {
    /// Fetch-plane traffic: no browser action exists to attribute it to.
    NotApplicable,
    /// The request started during `observe` or navigation, before any action opened an epoch.
    BeforeFirstEpoch,
    /// The action produced no receipt, so no epoch was opened for it.
    NoReceipt,
    /// A proxy flow that matched no epoch window and no CDP request.
    UnmatchedProxyFlow,
}

impl UnattributedReason {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::BeforeFirstEpoch => "before_first_epoch",
            Self::NoReceipt => "no_receipt",
            Self::UnmatchedProxyFlow => "unmatched_proxy_flow",
        }
    }
}

/// Application protocol a request was carried over, as the capture backend saw it
/// (`protocols_disabled` of a proxy-mode session).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum Protocol {
    /// HTTP/1.0 or HTTP/1.1 over TCP.
    #[serde(rename = "http/1.1")]
    Http11,
    /// HTTP/2 (`h2`, or `h2c` with prior knowledge).
    #[serde(rename = "h2")]
    H2,
    /// HTTP/3 over QUIC; only Chromium reports it, the proxy backend disables it.
    #[serde(rename = "h3")]
    H3,
}

impl Protocol {
    /// Stable ALPN-style name, identical to the serde form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http11 => "http/1.1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }
}

/// Placeholder a capture task writes over a credential header value before the event
/// enters any queue. The observe `Redactor` leaves such values alone.
pub const REDACTED_PLACEHOLDER: &str = "[redacted]";

/// Header names (lower-case) whose values the egress proxy drops before a flow leaves
/// the proxy task; the observe `Redactor` applies its wider list afterwards.
pub const PROXY_DENIED_HEADERS: &[&str] = &["authorization", "cookie", "set-cookie", "proxy-authorization"];

/// Bytes of a body a capture backend hashes before giving up.
pub const BODY_DIGEST_PREFIX: usize = 64 * 1024;

/// Domain tag of [`BodyDigest`].
pub const BODY_DIGEST_DOMAIN: &str = "crawlx/body-prefix/v1";

/// Digest of the first [`BODY_DIGEST_PREFIX`] bytes of a body plus its full length.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct BodyDigest {
    /// `BLAKE3(BODY_DIGEST_DOMAIN || prefix)`.
    pub digest: crate::hash::Digest,
    /// Full body length in bytes (the hashed prefix may be shorter).
    pub len: u64,
    /// `len` exceeds [`BODY_DIGEST_PREFIX`]: only the prefix was hashed.
    pub truncated: bool,
}

impl BodyDigest {
    /// Digest of `prefix` (at most [`BODY_DIGEST_PREFIX`] bytes; longer input is cut) for a
    /// body of `len` bytes in total.
    #[must_use]
    pub fn of_prefix(prefix: &[u8], len: u64) -> Self {
        let cut = &prefix[..prefix.len().min(BODY_DIGEST_PREFIX)];
        Self {
            digest: crate::hash::Digest::of(BODY_DIGEST_DOMAIN, cut),
            len,
            truncated: u64::try_from(BODY_DIGEST_PREFIX).is_ok_and(|p| len > p),
        }
    }
}

/// Which plane produced a [`ProxyFlow`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProxyFlowSource {
    /// A client of the loopback egress proxy (Chromium).
    Browser,
    /// The HTTP fetch plane's own client, which does not use the proxy.
    FetchPlane,
}

/// Byte counts of an opaque `CONNECT` tunnel.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct TunnelStats {
    /// Bytes the client sent into the tunnel.
    pub bytes_up: u64,
    /// Bytes the upstream sent back through the tunnel.
    pub bytes_down: u64,
}

/// One flow seen by the egress proxy (or the fetch plane), before epoch attribution
/// (proxy backend). Credential header values are already replaced by
/// [`REDACTED_PLACEHOLDER`] in the capture task; URL/query redaction happens in the
/// observe layer before the event is persisted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ProxyFlow {
    /// Who produced the flow.
    pub source: ProxyFlowSource,
    /// HTTP method; `CONNECT` for a tunnel.
    pub method: String,
    /// Absolute request URL; the authority-form target (`host:port`) for a tunnel.
    pub url: String,
    /// Upstream response status; `None` for a tunnel or when no response arrived.
    pub status: Option<u16>,
    /// Protocol of the client leg (and, for HTTP/2, of the upstream leg too).
    pub protocol: Protocol,
    /// Request headers in wire order, credential values replaced.
    pub request_headers: Vec<(String, String)>,
    /// Response headers in wire order, credential values replaced.
    pub response_headers: Vec<(String, String)>,
    /// Request body digest; `None` when the request had no body.
    pub request_body: Option<BodyDigest>,
    /// Response body digest; `None` when no body was observed.
    pub response_body: Option<BodyDigest>,
    /// Set for a `CONNECT` tunnel: the tunnel is opaque, so `status` and headers are absent.
    pub tunnel: Option<TunnelStats>,
    /// Loopback address of the client connection (`None` for fetch-plane flows).
    pub peer: Option<std::net::SocketAddr>,
    /// When the request reached the proxy.
    pub started_at: crate::time::Timestamp,
    /// When the response body (or the tunnel) ended.
    pub finished_at: crate::time::Timestamp,
}

/// One captured request/response, already redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TrafficEvent {
    /// Capture order within the context, starting at 1 and increasing by 1 per event.
    pub seq: u64,
    /// Network epoch (the span since the last action) the request is attributed to; `None` if outside any epoch.
    pub epoch_id: Option<crate::ids::NetworkEpochId>,
    /// Why `epoch_id` is `None`; `None` when the event is attributed (the trail verifier enforces this).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unattributed_reason: Option<UnattributedReason>,
    /// Who issued the request.
    pub origin: TrafficOrigin,
    /// HTTP method, e.g. `GET`.
    pub method: String,
    /// Request URL, already redacted.
    pub url: String,
    /// HTTP response status; `None` if no response arrived (failed or still in flight).
    pub status: Option<u16>,
    /// Request headers as name/value pairs in wire order, with secrets redacted.
    pub request_headers: Vec<(String, String)>,
    /// Response headers as name/value pairs in wire order, with secrets redacted.
    pub response_headers: Vec<(String, String)>,
    /// Stored request body; `None` if no body or it was not captured.
    pub request_body: Option<crate::ids::ArtifactRef>,
    /// Stored response body; `None` if no body or it was not captured.
    pub response_body: Option<crate::ids::ArtifactRef>,
    /// The request went to a different origin than the page that issued it.
    pub third_party: bool,
    /// The request finished after the epoch settled, so its attribution to the action is low-confidence.
    pub late: bool,
    /// Application protocol the capture backend observed; `None` when the backend did not report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// When the request started.
    pub started_at: crate::time::Timestamp,
    /// When the request finished or failed; `None` if it had not by the time of capture.
    pub finished_at: Option<crate::time::Timestamp>,
}
