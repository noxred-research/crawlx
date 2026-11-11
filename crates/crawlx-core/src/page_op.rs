//! Caller-driven page operations of the scrape engine: what the compatibility API
//! `actions[]`, `mobile`, `location`, `blockAds` and `screenshot`/`pdf` options need from a
//! browser context beyond the journaled [`crate::BrowserAction`] vocabulary.
//!
//! [`crate::BrowserContext::page_op`] executes one [`PageOp`]. Contexts that cannot (the scripted
//! fake, decorators that do not forward) answer [`crate::BrowserError::Unsupported`]. None of
//! these operations mutates server state on its own: input that does (click, write, press,
//! scroll) stays a [`crate::BrowserAction`] so it is adjudicated and journaled.

use crate::observation::RuntimeLocator;
use crate::parser_memory::{AdmittedBytes, AdmittedText};
use serde::{Deserialize, Serialize};

/// Per-request emulation, applied before the navigation (CDP
/// `Emulation.setDeviceMetricsOverride`, `setUserAgentOverride`, `setLocaleOverride`,
/// `setTimezoneOverride`, `setGeolocationOverride`).
///
/// The value is context-wide: every open tab and child frame carries it and every tab or frame
/// attached later (popups, new iframes) receives it before its first request, so what a caller
/// asked for is stable across the whole context.
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
    /// Device pixel ratio in thousandths (`2000` is `devicePixelRatio === 2`), within
    /// [`DEVICE_SCALE_MIN_MILLI`]..=[`DEVICE_SCALE_MAX_MILLI`]; `None` keeps `1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_scale_milli: Option<u32>,
    /// Position `navigator.geolocation` reports; the page can read it without a prompt, so
    /// it is only ever set by an explicit request. `None` leaves geolocation unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geolocation: Option<GeoPosition>,
}

/// Smallest accepted device pixel ratio, in thousandths.
pub const DEVICE_SCALE_MIN_MILLI: u32 = 500;
/// Largest accepted device pixel ratio, in thousandths.
pub const DEVICE_SCALE_MAX_MILLI: u32 = 4_000;

/// A geographic position in fixed-point micro-degrees, so emulation values compare and
/// serialize exactly ([`Emulation`] is `Eq`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct GeoPosition {
    /// Latitude in millionths of a degree, `-90_000_000..=90_000_000`.
    pub latitude_e6: i32,
    /// Longitude in millionths of a degree, `-180_000_000..=180_000_000`.
    pub longitude_e6: i32,
    /// Accuracy radius in metres, `1..=`[`GeoPosition::MAX_ACCURACY_M`].
    pub accuracy_m: u32,
}

impl GeoPosition {
    /// Accuracy radius used when the caller names none, in metres.
    pub const DEFAULT_ACCURACY_M: u32 = 100;
    /// Largest accepted accuracy radius, in metres.
    pub const MAX_ACCURACY_M: u32 = 100_000;

    /// A validated position.
    ///
    /// # Errors
    /// The name of the first member outside its range.
    pub const fn new(latitude_e6: i32, longitude_e6: i32, accuracy_m: u32) -> Result<Self, &'static str> {
        if latitude_e6 < -90_000_000 || latitude_e6 > 90_000_000 {
            return Err("latitude");
        }
        if longitude_e6 < -180_000_000 || longitude_e6 > 180_000_000 {
            return Err("longitude");
        }
        if accuracy_m == 0 || accuracy_m > Self::MAX_ACCURACY_M {
            return Err("accuracy");
        }
        Ok(Self {
            latitude_e6,
            longitude_e6,
            accuracy_m,
        })
    }

    /// Latitude in degrees.
    #[must_use]
    pub fn latitude(&self) -> f64 {
        f64::from(self.latitude_e6) / 1e6
    }

    /// Longitude in degrees.
    #[must_use]
    pub fn longitude(&self) -> f64 {
        f64::from(self.longitude_e6) / 1e6
    }
}

/// Which kind of rule a blocked-resource pattern came from.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BlockClass {
    /// Advertising, measurement and consent hosts of the built-in list.
    Ads,
    /// A host the caller named.
    Domain,
    /// Web fonts, matched by URL extension.
    Font,
    /// Audio and video, matched by URL extension.
    Media,
    /// Raster and vector images, matched by URL extension.
    Image,
}

impl BlockClass {
    /// Stable name for metadata and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ads => "ads",
            Self::Domain => "domain",
            Self::Font => "font",
            Self::Media => "media",
            Self::Image => "image",
        }
    }

    /// Is the class a resource type that the browser can only match by the URL's extension?
    #[must_use]
    pub const fn by_extension(self) -> bool {
        matches!(self, Self::Font | Self::Media | Self::Image)
    }
}

/// One `*`-wildcard URL pattern of a block list and the rule class it belongs to.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlockEntry {
    /// `Network.setBlockedURLs` wildcard pattern.
    pub pattern: String,
    /// Rule class the pattern was derived from.
    pub class: BlockClass,
}

/// A versioned block list: what [`PageOp::BlockResources`] installs, replacing the previous
/// list of the context.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ResourceBlockSpec {
    /// Version of the list the entries were taken from.
    pub list_version: String,
    /// Patterns in a stable order, each with its class.
    pub entries: Vec<BlockEntry>,
}

/// What installing a [`ResourceBlockSpec`] reached.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlockInstall {
    /// Patterns installed per session.
    pub patterns: u32,
    /// Tab and child-frame sessions the list was installed on.
    pub sessions_applied: u32,
    /// Sessions that rejected the list while still open (never silently dropped).
    pub sessions_failed: u32,
}

/// Which parts of a document [`PageOp::FlattenedHtml`] folds into the serialization.
///
/// The flattened text is for extraction only: the live DOM is only read, never changed, and
/// the locators, backend node ids and epochs the actor uses for actions are untouched.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FlattenSpec {
    /// Inline the content of open shadow roots.
    #[serde(default = "FlattenSpec::on")]
    pub shadow_dom: bool,
    /// Inline the document of every readable iframe.
    #[serde(default = "FlattenSpec::on")]
    pub frames: bool,
    /// Most frames (the main document included) folded in; the rest are reported as skipped.
    #[serde(default = "FlattenSpec::default_max_frames")]
    pub max_frames: u32,
}

impl FlattenSpec {
    /// Most frames any request may ask for.
    pub const MAX_FRAMES_LIMIT: u32 = 64;
    /// Deepest iframe nesting that is folded in; deeper frames are reported as skipped.
    pub const MAX_DEPTH: u32 = 5;

    const fn on() -> bool {
        true
    }

    const fn default_max_frames() -> u32 {
        16
    }
}

impl Default for FlattenSpec {
    fn default() -> Self {
        Self {
            shadow_dom: true,
            frames: true,
            max_frames: Self::default_max_frames(),
        }
    }
}

/// Why a frame is, or is not, part of the flattened text.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FrameStatus {
    /// The document's markup is part of the flattened text.
    Flattened,
    /// The frame belongs to another origin than its parent and the browser keeps its document
    /// out of reach of the parent's script.
    CrossOrigin,
    /// The frame is nested deeper than [`FlattenSpec::MAX_DEPTH`].
    DepthLimit,
    /// [`FlattenSpec::max_frames`] frames were already folded in.
    FrameLimit,
    /// The frame has no readable document (not loaded, sandboxed or destroyed meanwhile).
    Unavailable,
}

/// Where one frame's text in the flattened serialization came from.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FrameProvenance {
    /// Position in document order; `0` is the main document.
    pub ordinal: u32,
    /// Ordinal of the embedding document; `None` for the main document.
    pub parent: Option<u32>,
    /// Nesting depth, `0` for the main document.
    pub depth: u32,
    /// `scheme://host[:port]` of the frame: observed from the document when it was flattened,
    /// declared by the iframe's `src` otherwise (see `origin_observed`).
    pub origin: String,
    /// `true` when `origin` is the origin the browser reports for the loaded document.
    pub origin_observed: bool,
    /// Document URL without credentials, query or fragment.
    pub url: String,
    /// Whether and why the frame's markup is in the text.
    pub status: FrameStatus,
    /// Open shadow roots inlined in this document (not counting nested frames).
    pub shadow_roots: u32,
}

/// The result of [`PageOp::FlattenedHtml`].
#[derive(Clone, PartialEq, Debug)]
pub struct FlattenedDocument {
    /// Serialization with shadow roots and readable iframes folded in as
    /// `<crawlx-shadow>` / `<crawlx-frame data-crawlx-frame data-crawlx-origin>` elements.
    pub html: AdmittedText,
    /// Current main-document URL.
    pub url: String,
    /// One entry per frame the walk met, main document first, in document order.
    pub frames: Vec<FrameProvenance>,
    /// Frames met after the list reached its bound (256): their markup is not in the text.
    pub frames_omitted: u32,
}

/// What a page reports about the device it runs on, measured by script in the page itself.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMeasurement {
    /// `(innerWidth, innerHeight)` in CSS pixels. A mobile emulation lays a page without a
    /// viewport declaration out at 980 px, so this can differ from the requested device size.
    pub viewport: (u32, u32),
    /// `(screen.width, screen.height)` in CSS pixels: the emulated device size.
    pub screen: (u32, u32),
    /// `devicePixelRatio` in thousandths.
    pub device_pixel_ratio_milli: u32,
    /// `navigator.userAgent`.
    pub user_agent: String,
    /// `navigator.language`.
    pub language: String,
    /// `Intl.DateTimeFormat().resolvedOptions().timeZone`.
    pub time_zone: String,
    /// `navigator.maxTouchPoints`.
    pub max_touch_points: u32,
    /// `matchMedia('(pointer: coarse)')`.
    pub pointer_coarse: bool,
    /// What `navigator.geolocation.getCurrentPosition` answered: the position, or `None` with
    /// `geolocation_error`.
    pub geolocation: Option<GeoPosition>,
    /// `unavailable`, `denied`, `timeout` or `insecure_context` when no position was read;
    /// absent when one was read or geolocation was not probed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geolocation_error: Option<String>,
}

/// A named device the matrix measures. Each preset is a declared emulation of a device class on
/// the running Chromium build, not an attempt to look like another browser.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DevicePreset {
    /// Desktop viewport, mouse pointer, the browser's own `User-Agent`.
    Desktop,
    /// Phone viewport, touch, `Mobile` user agent of the running Chromium major.
    Phone,
    /// Tablet viewport, touch, user agent of the running Chromium major without `Mobile`.
    Tablet,
}

/// Leading tokens of the reduced `User-Agent` a Chromium on Android sends.
const ANDROID_UA_PREFIX: &str = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "; // wire-compat: standard user-agent token

impl DevicePreset {
    /// Every preset, in the order the matrix lists them.
    pub const ALL: [Self; 3] = [Self::Desktop, Self::Phone, Self::Tablet];

    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Phone => "phone",
            Self::Tablet => "tablet",
        }
    }

    /// The emulation of the preset for a Chromium build whose version string is
    /// `chromium_version` (`155.0.8059.84`); only its major number is used, like the reduced
    /// `User-Agent` the browser itself sends. The locale is `locale`.
    #[must_use]
    pub fn emulation(self, chromium_version: &str, locale: &str) -> Emulation {
        let major = chromium_version.split('.').next().unwrap_or("0");
        let (viewport, scale, mobile, user_agent) = match self {
            Self::Desktop => ((1280, 800), 1_000, false, None),
            Self::Phone => (
                (412, 915),
                2_625,
                true,
                Some(format!(
                    "{ANDROID_UA_PREFIX}Chrome/{major}.0.0.0 Mobile Safari/537.36"
                )),
            ),
            Self::Tablet => (
                (800, 1280),
                2_000,
                true,
                Some(format!("{ANDROID_UA_PREFIX}Chrome/{major}.0.0.0 Safari/537.36")),
            ),
        };
        Emulation {
            viewport: Some(viewport),
            mobile,
            user_agent,
            accept_language: Some(locale.to_owned()),
            locale: Some(locale.to_owned()),
            timezone: Some("UTC".to_owned()),
            device_scale_milli: Some(scale),
            geolocation: None,
        }
    }
}

/// One row of the device matrix: what a preset asked for and what the browser then reported.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMatrixEntryV1 {
    /// The preset.
    pub preset: DevicePreset,
    /// The emulation that was applied.
    pub requested: Emulation,
    /// What the page measured under it.
    pub measured: DeviceMeasurement,
    /// `true` when `violations` is empty.
    pub coherent: bool,
    /// Stable codes of every measured value that disagrees with the request or with the
    /// device class (`viewport_mismatch`, `scale_mismatch`, `user_agent_mismatch`,
    /// `user_agent_build_mismatch`, `mobile_token_mismatch`, `touch_mismatch`,
    /// `language_mismatch`, `time_zone_mismatch`).
    pub violations: Vec<String>,
}

impl DeviceMatrixEntryV1 {
    /// Compare `measured` against `requested` for `preset` on a build whose Chromium version
    /// is `chromium_version`.
    #[must_use]
    pub fn check(
        preset: DevicePreset,
        requested: Emulation,
        measured: DeviceMeasurement,
        chromium_version: &str,
    ) -> Self {
        let mut violations = Vec::new();
        if requested.viewport.is_some_and(|v| v != measured.screen) {
            violations.push("viewport_mismatch".to_owned());
        }
        if requested
            .device_scale_milli
            .is_some_and(|s| s != measured.device_pixel_ratio_milli)
        {
            violations.push("scale_mismatch".to_owned());
        }
        if requested
            .user_agent
            .as_deref()
            .is_some_and(|ua| ua != measured.user_agent)
        {
            violations.push("user_agent_mismatch".to_owned());
        }
        let major = chromium_version.split('.').next().unwrap_or("0");
        if !measured.user_agent.contains(&format!("Chrome/{major}.")) {
            violations.push("user_agent_build_mismatch".to_owned());
        }
        let phone_like = requested.mobile && preset == DevicePreset::Phone;
        if measured.user_agent.contains(" Mobile") != phone_like {
            violations.push("mobile_token_mismatch".to_owned());
        }
        if (measured.max_touch_points > 0) != requested.mobile {
            violations.push("touch_mismatch".to_owned());
        }
        if requested
            .locale
            .as_deref()
            .is_some_and(|l| !measured.language.starts_with(l))
        {
            violations.push("language_mismatch".to_owned());
        }
        if requested
            .timezone
            .as_deref()
            .is_some_and(|z| z != measured.time_zone)
        {
            violations.push("time_zone_mismatch".to_owned());
        }
        Self {
            preset,
            requested,
            measured,
            coherent: violations.is_empty(),
            violations,
        }
    }
}

/// The browser build a [`DeviceMatrixV1`] was measured on.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceBuildV1 {
    /// Chromium version string the running browser reports.
    pub chromium_version: String,
    /// `true` when that version is the pinned one.
    pub pinned: bool,
}

/// Measured emulated-device matrix of one browser build (capability evidence). Values are what
/// the page reported under each preset on that build; the matrix makes no claim about evading
/// detection or matching another browser's fingerprint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMatrixV1 {
    /// Layout version of this value (1).
    pub schema_version: u32,
    /// The measured build.
    pub build: DeviceBuildV1,
    /// One entry per [`DevicePreset`], in [`DevicePreset::ALL`] order.
    pub entries: Vec<DeviceMatrixEntryV1>,
    /// Always `false`: the matrix is not a stealth or detection-evasion claim.
    pub stealth_claim: bool,
}

impl DeviceMatrixV1 {
    /// Layout version written by this crate.
    pub const VERSION: u32 = 1;

    /// A matrix of `entries` measured on `build`.
    #[must_use]
    pub fn new(build: DeviceBuildV1, entries: Vec<DeviceMatrixEntryV1>) -> Self {
        Self {
            schema_version: Self::VERSION,
            build,
            entries,
            stealth_claim: false,
        }
    }

    /// Does every entry agree with its request and device class?
    #[must_use]
    pub fn coherent(&self) -> bool {
        self.entries.iter().all(|e| e.coherent)
    }

    /// Is the matrix small enough to publish as capability evidence: at most one entry per
    /// preset and bounded strings throughout?
    #[must_use]
    pub fn within_bounds(&self) -> bool {
        self.build.chromium_version.len() <= 256
            && self.entries.len() <= DevicePreset::ALL.len()
            && self.entries.iter().all(|entry| {
                entry.violations.len() <= 16
                    && entry.violations.iter().all(|code| code.len() <= 64)
                    && entry.measured.user_agent.len() <= 1024
                    && entry.measured.language.len() <= 64
                    && entry.measured.time_zone.len() <= 64
                    && entry
                        .requested
                        .user_agent
                        .as_ref()
                        .is_none_or(|ua| ua.len() <= 1024)
            })
    }
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
/// opacity, hit testing, enabled state or stability. This is not full reference-driver parity.
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
    /// Install a versioned block list (`Network.setBlockedURLs` with its patterns) on every
    /// tab and frame of the context, replacing the previous list.
    BlockResources(ResourceBlockSpec),
    /// The main document serialized like [`PageOp::Html`] with shadow roots and readable
    /// iframes folded in, and the provenance of every frame. Read-only: the live DOM and
    /// the identity of its elements for actions stay as they are.
    FlattenedHtml(FlattenSpec),
    /// Measure viewport, pixel ratio, `User-Agent`, language, time zone, touch support and,
    /// when asked, geolocation by script in the active tab's page.
    MeasureDevice {
        /// Also read `navigator.geolocation` (waits at most a few seconds).
        probe_geolocation: bool,
    },
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
    /// Capture bounded evidence through the configured policy sink.
    Capture(crate::browser_capture::CaptureSpec),
    /// Download an explicitly authorized attachment without exposing a host path.
    Download(crate::browser_download::DownloadSpec),
    /// Project bounded captured responses and diagnostic messages without draining raw traffic.
    CaptureProjection,
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
            Self::Capture(_) => "capture",
            Self::Download(_) => "download",
            Self::CaptureProjection => "capture_projection",
            Self::WaitForSelector { .. } => "wait_for_selector",
            Self::ResolveAll { .. } => "resolve_all",
            Self::BlockResources(_) => "block_resources",
            Self::FlattenedHtml(_) => "flattened_html",
            Self::MeasureDevice { .. } => "measure_device",
        }
    }
}

/// What a [`PageOp`] returned.
#[derive(Clone, PartialEq, Debug)]
pub enum PageOpResult {
    /// The operation has no result.
    Done,
    /// Policy-owned retained browser evidence, never raw bytes or a host path.
    Capture(crate::browser_capture::CaptureArtifact),
    /// Bounded metadata with explicit unavailable and dropped-record states.
    Projection(crate::browser_projection::BrowserProjection),
    /// A JSON value (`EvaluateScript`).
    Json(serde_json::Value),
    /// The serialized DOM and the document URL (`Html`).
    Html {
        /// `<!DOCTYPE ...>` plus `outerHTML` of the document element. Cloning shares the
        /// bytes and their byte reservation; copying them needs a new reservation.
        html: AdmittedText,
        /// Current document URL.
        url: String,
    },
    /// Encoded bytes (`Screenshot`: PNG or JPEG, `PrintToPdf`: PDF).
    Bytes {
        /// The encoded image or document. Cloning shares the bytes and their reservation.
        bytes: AdmittedBytes,
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
    /// What installing a block list reached (`BlockResources`).
    BlockInstalled(BlockInstall),
    /// The serialization with shadow roots and readable iframes folded in (`FlattenedHtml`).
    Flattened(FlattenedDocument),
    /// What the active tab's page reports about its device (`MeasureDevice`).
    Device(DeviceMeasurement),
}
