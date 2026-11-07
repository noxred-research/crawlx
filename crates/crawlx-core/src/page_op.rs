//! Caller-driven page operations of the scrape engine: what the Firecrawl
//! `actions[]`, `mobile`, `location`, `blockAds` and `screenshot`/`pdf` options need from a
//! browser context beyond the journaled [`crate::BrowserAction`] vocabulary.
//!
//! [`crate::BrowserContext::page_op`] executes one [`PageOp`]. Contexts that cannot (the scripted
//! fake, decorators that do not forward) answer [`crate::BrowserError::Unsupported`]. None of
//! these operations mutates server state on its own: input that does (click, write, press,
//! scroll) stays a [`crate::BrowserAction`] so it is adjudicated and journaled.

use crate::observation::RuntimeLocator;
use serde::{Deserialize, Serialize};

/// Per-request emulation, applied before the navigation (CDP
/// `Emulation.setDeviceMetricsOverride`, `setUserAgentOverride`, `setLocaleOverride`,
/// `setTimezoneOverride`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct Emulation {
    /// Viewport `(width, height)` in CSS pixels; `None` keeps the context's.
    pub viewport: Option<(u32, u32)>,
    /// Report a touch phone (`mobile` flag of the device metrics override).
    pub mobile: bool,
    /// `User-Agent` override.
    pub user_agent: Option<String>,
    /// `Accept-Language` header value (sent with the user-agent override).
    pub accept_language: Option<String>,
    /// BCP 47 locale for `Intl` and `navigator.language`.
    pub locale: Option<String>,
    /// IANA time zone id.
    pub timezone: Option<String>,
}

/// Screenshot request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct ShotSpec {
    /// Capture the whole scrollable page.
    pub full_page: bool,
    /// JPEG quality 1..=100; `None` captures PNG.
    pub quality: Option<u8>,
    /// Viewport override for this capture (restored afterwards).
    pub viewport: Option<(u32, u32)>,
}

/// `Page.printToPDF` request.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PdfSpec {
    /// Paper format name (`A4`, `Letter`, ...); `None` is `Letter`.
    pub format: Option<String>,
    /// Landscape orientation.
    pub landscape: bool,
    /// Scale factor, 0.1..=2.0.
    pub scale: f32,
}

/// State awaited by a CSS selector wait, using only the first match in document order.
///
/// Visibility requires a positive-width, positive-height layout box and computed
/// `visibility` other than `hidden` or `collapse`. It does not require viewport intersection,
/// opacity, hit testing, enabled state or stability. This is not full Playwright parity.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
#[must_use]
pub enum SelectorState {
    /// The first matching element exists (default).
    #[default]
    Attached,
    /// The first matching element exists and is visible.
    Visible,
    /// No element matches, or the first matching element is not visible.
    Hidden,
    /// No element matches, regardless of visibility.
    Detached,
}

/// One operation.
#[derive(Clone, PartialEq, Debug)]
pub enum PageOp {
    /// Apply [`Emulation`] to the active tab.
    Emulate(Emulation),
    /// Cancel requests whose URL matches one of these `*`-wildcard patterns
    /// (`Network.setBlockedURLs`); replaces the previous list.
    BlockUrls(Vec<String>),
    /// The response of the latest main-frame document navigation of the active tab (status,
    /// headers, media type), for callers that render a page and still report the HTTP facts.
    DocumentResponse,
    /// Evaluate `script` in the page's main world (awaiting a returned promise) and return its
    /// JSON value.
    EvaluateScript {
        /// Script source: an expression or a function body wrapped by the caller.
        script: String,
    },
    /// Pin exactly one virtualized container and capture its initial rows.
    BeginVirtualRows(crate::dom_ops::VirtualRowsSpec),
    /// Capture the next settled window from the pinned container.
    ReadVirtualRows,
    /// Resolve only the pinned original container for a native journaled scroll.
    VirtualRowsTarget,
    /// Restore the original container position and release the pin.
    RestoreVirtualRows,
    /// The serialized DOM of the main document plus its current URL.
    Html,
    /// Capture a screenshot.
    Screenshot(ShotSpec),
    /// Print the page to PDF.
    PrintToPdf(PdfSpec),
    /// Wait until the first CSS match satisfies `state`, at most `timeout_ms`.
    ///
    /// See [`SelectorState`] for the narrow visibility contract. Invalid CSS returns
    /// [`crate::BrowserError::Script`], rather than a timeout.
    WaitForSelector {
        /// CSS selector.
        selector: String,
        /// Desired state of the first match.
        state: SelectorState,
        /// Longest wait in milliseconds.
        timeout_ms: u32,
    },
    /// Every element matching CSS `selector` as a locator valid at the current epoch, in
    /// document order, at most `limit`.
    ResolveAll {
        /// CSS selector.
        selector: String,
        /// Most locators returned.
        limit: u32,
    },
}

impl PageOp {
    /// Stable name for logs and audit events.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Emulate(_) => "emulate",
            Self::BlockUrls(_) => "block_urls",
            Self::DocumentResponse => "document_response",
            Self::EvaluateScript { .. } => "evaluate_script",
            Self::BeginVirtualRows(_) => "begin_virtual_rows",
            Self::ReadVirtualRows => "read_virtual_rows",
            Self::VirtualRowsTarget => "virtual_rows_target",
            Self::RestoreVirtualRows => "restore_virtual_rows",
            Self::Html => "html",
            Self::Screenshot(_) => "screenshot",
            Self::PrintToPdf(_) => "print_to_pdf",
            Self::WaitForSelector { .. } => "wait_for_selector",
            Self::ResolveAll { .. } => "resolve_all",
        }
    }
}

/// What a [`PageOp`] returned.
#[derive(Clone, PartialEq, Debug)]
pub enum PageOpResult {
    /// The operation has no result.
    Done,
    /// A JSON value (`EvaluateScript`).
    Json(serde_json::Value),
    /// The serialized DOM and the document URL (`Html`).
    Html {
        /// `<!DOCTYPE ...>` plus `outerHTML` of the document element.
        html: String,
        /// Current document URL.
        url: String,
    },
    /// Encoded bytes (`Screenshot`: PNG or JPEG, `PrintToPdf`: PDF).
    Bytes {
        /// The encoded image or document.
        bytes: Vec<u8>,
        /// Media type: `image/png`, `image/jpeg` or `application/pdf`.
        content_type: &'static str,
    },
    /// Locators (`ResolveAll`).
    Locators(Vec<RuntimeLocator>),
    /// Whether the requested selector state was reached (`WaitForSelector`).
    Found(bool),
    /// Bounded diagnostic window; never a replacement for final DOM.
    VirtualRows(crate::dom_ops::VirtualRowsWindow),
    /// Original-position cleanup outcome.
    VirtualRowsRestored(crate::dom_ops::VirtualRowsRestoration),
    /// The main-document response (`DocumentResponse`).
    Response {
        /// HTTP status; `None` when no document response was observed (e.g. `about:blank`).
        status: Option<u16>,
        /// Response headers, lower-case names, credential headers redacted like traffic capture.
        headers: Vec<(String, String)>,
        /// `Response.mimeType` of the document.
        content_type: Option<String>,
    },
}
