//! Caller-driven page operations (`BrowserContext::page_op`): the emulation,
//! request blocking, script evaluation, serialization, screenshot and PDF operations the
//! scrape engine needs beyond the journaled `BrowserAction` vocabulary.
//!
//! `BlockUrls`, `BlockResources` and `Emulate` are context-wide: the value is stored in
//! `State::overrides`, applied to every open tab and child-frame session, and re-applied by
//! `setup_tab` / `setup_frame` ([`apply_overrides`]) to the tabs and frames attached later
//! (popups, new iframes). An emulation carries the viewport, device pixel ratio, user agent,
//! locale, time zone and geolocation; the geolocation permission is granted for the whole
//! browser context while one is set. Every other operation targets the active tab.
//! Script-visible reads (`Html`, `FlattenedHtml`, `MeasureDevice`, `EvaluateScript`,
//! `WaitForSelector`) run in the page's main world with `Runtime.evaluate`, which needs neither
//! `Runtime.enable` nor the isolated world, so they work under every launch profile; they read
//! the page and never change it. Every command is bounded by an explicit timeout.

use super::selector::describe;
use super::state::State;
use super::{CdpContext, Ctl};
use crate::cdp::CdpSession;
use crawlx_core::browser::BrowserError;
use crawlx_core::ids::{BackendNodeId, FrameId, TabId};
use crawlx_core::observation::RuntimeLocator;
use crawlx_core::page_op::{
    BlockInstall, DeviceBuildV1, DeviceMatrixEntryV1, DeviceMatrixV1, DeviceMeasurement, DevicePreset,
    Emulation, FlattenSpec, FlattenedDocument, FrameProvenance, GeoPosition, PageOp, PageOpResult, PdfSpec,
    ResourceBlockSpec, SelectorState, ShotSpec,
};
use crawlx_core::parser_memory::{
    AdmittedBytes, AdmittedText, Budgeted, ByteAdmissionError, ByteBudget, BytePermit,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Longest a script may run (`EvaluateScript`, one `Html` serialization).
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause between two `WaitForSelector` probes.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Shortest budget of one `WaitForSelector` probe, so a wait of 0 ms still probes once.
const MIN_PROBE: Duration = Duration::from_millis(500);
/// Longest edge of a full-page screenshot in CSS pixels (Chromium cannot allocate a larger
/// texture).
const MAX_SHOT_EDGE: u32 = 16_384;
/// Touch points reported while `Emulation::mobile` is set.
const MAX_TOUCH_POINTS: u8 = 5;
/// Shallow-DOM-to-text serializer that folds shadow roots and readable iframes in; a function
/// expression taking the [`FlattenSpec`] as JSON.
const FLATTEN_SCRIPT: &str = include_str!("../../data/flatten_document.js");
/// Reads viewport, pixel ratio, user agent, language, time zone, touch support and, on
/// request, geolocation; a function expression taking the probe flag.
const MEASURE_SCRIPT: &str = include_str!("../../data/measure_device.js");

/// `DOCTYPE` plus `outerHTML` of the document element, and the document URL.
const HTML_SCRIPT: &str = r#"(() => {
  const d = document.doctype;
  let head = '';
  if (d) {
    head = '<!DOCTYPE ' + d.name;
    if (d.publicId) { head += ' PUBLIC "' + d.publicId + '"'; }
    else if (d.systemId) { head += ' SYSTEM'; }
    if (d.systemId) { head += ' "' + d.systemId + '"'; }
    head += '>';
  }
  const root = document.documentElement;
  return { html: head + (root ? root.outerHTML : ''), url: location.href };
})()"#;

/// What a session is: a tab (page target) or an auto-attached out-of-process child frame.
/// Frames take the per-target overrides but not the device metrics, which Chromium
/// propagates from the main frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SessionKind {
    /// A page target.
    Tab,
    /// An out-of-process iframe target.
    Frame,
}

/// Apply the stored context-wide overrides (blocked URLs, emulation) to one freshly attached
/// tab or child-frame session. Runs after the request controls and the configured locale, so
/// an emulated `User-Agent`, locale or viewport wins over the context defaults.
///
/// # Errors
/// The protocol error of the first command Chromium rejects: an override that was asked for
/// is never dropped silently.
pub(super) async fn apply_overrides(
    sess: &CdpSession,
    ctl: &Ctl,
    state: &Mutex<State>,
    kind: SessionKind,
) -> Result<(), BrowserError> {
    let overrides = state.lock().overrides.clone();
    if !overrides.block_urls.is_empty() {
        set_blocked_urls(sess, &overrides.block_urls).await?;
    }
    if let Some(em) = &overrides.emulation {
        apply_emulation(sess, ctl, kind, em, None, false).await?;
    }
    Ok(())
}

/// `Network.setBlockedURLs` with `patterns` (empty clears the list).
async fn set_blocked_urls(sess: &CdpSession, patterns: &[String]) -> Result<(), BrowserError> {
    sess.send("Network.setBlockedURLs", json!({ "urls": patterns }))
        .await
        .map(|_| ())
}

/// The viewport in effect: `viewport` (a per-capture override), else the emulation's, else
/// the context's.
fn viewport_of(ctl: &Ctl, em: &Emulation, viewport: Option<(u32, u32)>) -> (u32, u32) {
    viewport
        .or(em.viewport)
        .unwrap_or((ctl.config.viewport.width, ctl.config.viewport.height))
}

/// `Emulation.setDeviceMetricsOverride` parameters for [`viewport_of`] at the emulation's
/// device pixel ratio (1 without one), mobile per the emulation.
fn metrics_params(ctl: &Ctl, em: &Emulation, viewport: Option<(u32, u32)>) -> Value {
    let (width, height) = viewport_of(ctl, em, viewport);
    let scale = em
        .device_scale_milli
        .map_or(1.0, |milli| f64::from(milli) / 1000.0);
    let mut params = json!({
        "width": width, "height": height, "deviceScaleFactor": scale, "mobile": em.mobile,
    });
    // the screen follows an explicitly requested device size; without one it stays the
    // context's own, so clearing an emulation restores what the page saw before
    if viewport.or(em.viewport).is_some() {
        params["screenWidth"] = json!(width);
        params["screenHeight"] = json!(height);
    }
    params
}

/// The `User-Agent` of the context without any emulation (`fetch.userAgent`, else
/// `ContextConfig::user_agent`); `None` keeps the browser's own value.
fn base_user_agent(ctl: &Ctl) -> Option<&str> {
    ctl.config
        .request_controls
        .user_agent()
        .or(ctl.config.user_agent.as_deref())
}

/// Bring one session from `prev` (the emulation it carried, `None` for none) to `next`.
/// `existing` marks a session that may already carry a locale or time zone override (a
/// sweep of open sessions rather than a fresh attach): Chromium refuses to replace those, so
/// they are cleared first.
///
/// `next.user_agent` is always set when `next.accept_language` is (see
/// [`CdpContext::resolve_emulation`]): the override carries both or neither.
async fn apply_emulation(
    sess: &CdpSession,
    ctl: &Ctl,
    kind: SessionKind,
    next: &Emulation,
    prev: Option<&Emulation>,
    existing: bool,
) -> Result<(), BrowserError> {
    if kind == SessionKind::Tab
        && (next.viewport.is_some() || next.mobile || next.device_scale_milli.is_some() || prev.is_some())
    {
        sess.send(
            "Emulation.setDeviceMetricsOverride",
            metrics_params(ctl, next, None),
        )
        .await?;
    }
    if next.mobile || prev.is_some_and(|p| p.mobile) {
        let params = if next.mobile {
            json!({ "enabled": true, "maxTouchPoints": MAX_TOUCH_POINTS })
        } else {
            json!({ "enabled": false })
        };
        sess.send("Emulation.setTouchEmulationEnabled", params).await?;
    }
    if let Some(ua) = next.user_agent.as_deref() {
        let language = next.accept_language.as_deref().unwrap_or(&ctl.config.locale);
        sess.send(
            "Emulation.setUserAgentOverride",
            json!({ "userAgent": ua, "acceptLanguage": language }),
        )
        .await?;
    } else if prev.is_some_and(|p| p.user_agent.is_some()) {
        // back to the context's own User-Agent; an empty pair clears the override
        let params = match base_user_agent(ctl) {
            Some(ua) => json!({ "userAgent": ua, "acceptLanguage": ctl.config.locale }),
            None => json!({ "userAgent": "", "acceptLanguage": "" }),
        };
        sess.send("Emulation.setUserAgentOverride", params).await?;
    }
    if let Some(locale) = next.locale.as_deref() {
        set_locale(sess, locale, existing || prev.is_some()).await;
    } else if prev.is_some_and(|p| p.locale.is_some()) {
        set_locale(sess, &ctl.config.locale, true).await;
    }
    if let Some(zone) = next.timezone.as_deref() {
        if existing || prev.is_some() {
            sess.send("Emulation.setTimezoneOverride", json!({ "timezoneId": "" }))
                .await?;
        }
        sess.send("Emulation.setTimezoneOverride", json!({ "timezoneId": zone }))
            .await?;
    } else if prev.is_some_and(|p| p.timezone.is_some()) {
        sess.send("Emulation.setTimezoneOverride", json!({ "timezoneId": "" }))
            .await?;
    }
    if let Some(geo) = next.geolocation {
        sess.send(
            "Emulation.setGeolocationOverride",
            json!({
                "latitude": geo.latitude(),
                "longitude": geo.longitude(),
                "accuracy": f64::from(geo.accuracy_m),
            }),
        )
        .await?;
    } else if prev.is_some_and(|p| p.geolocation.is_some()) {
        sess.send("Emulation.setGeolocationOverride", json!({})).await?;
    }
    Ok(())
}

/// `Emulation.setLocaleOverride`, clearing the earlier override first when `clear_first`.
/// Some Chromium builds reject a second locale override; the `--lang` flag and the context's
/// locale already provide the default, so a rejection leaves that default in place.
async fn set_locale(sess: &CdpSession, locale: &str, clear_first: bool) {
    if clear_first {
        let _ = sess
            .send("Emulation.setLocaleOverride", json!({ "locale": "" }))
            .await;
    }
    if let Err(e) = sess
        .send("Emulation.setLocaleOverride", json!({ "locale": locale }))
        .await
    {
        tracing::debug!(error = %e, "locale override rejected by this Chromium build");
    }
}

/// Paper size in inches `(width, height)` of a format name; `None` is Letter.
fn paper_inches(format: Option<&str>) -> Result<(f64, f64), BrowserError> {
    let name = format.unwrap_or("Letter");
    Ok(match name.to_ascii_lowercase().as_str() {
        "letter" => (8.5, 11.0),
        "legal" => (8.5, 14.0),
        "tabloid" => (11.0, 17.0),
        "ledger" => (17.0, 11.0),
        "a0" => (33.1, 46.8),
        "a1" => (23.4, 33.1),
        "a2" => (16.54, 23.4),
        "a3" => (11.7, 16.54),
        "a4" => (8.27, 11.7),
        "a5" => (5.83, 8.27),
        "a6" => (4.13, 5.83),
        _ => return Err(BrowserError::Unsupported(format!("pdf paper format {name}"))),
    })
}

/// The message of a thrown value: the description up to its stack trace, else the thrown
/// primitive, else the exception text.
fn exception_message(details: &Value) -> String {
    let exception = details.get("exception");
    exception
        .and_then(|e| e.get("description"))
        .and_then(Value::as_str)
        .and_then(|d| d.split("\n    at ").next())
        .map(str::to_owned)
        .or_else(|| {
            exception
                .and_then(|e| e.get("value"))
                .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned))
        })
        .or_else(|| details.get("text").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "exception".to_owned())
}

/// By-value result of a main-world `Runtime.evaluate`; values JSON cannot carry (`NaN`,
/// `Infinity`, `BigInt`) come back as their source text.
///
/// # Errors
/// [`BrowserError::Script`] when the evaluation threw.
fn main_world_result(v: &Value) -> Result<Value, BrowserError> {
    if let Some(details) = v.get("exceptionDetails") {
        return Err(BrowserError::Script(exception_message(details)));
    }
    let result = v.get("result");
    if let Some(value) = result.and_then(|r| r.get("value")) {
        return Ok(value.clone());
    }
    Ok(result
        .and_then(|r| r.get("unserializableValue"))
        .and_then(Value::as_str)
        .map_or(Value::Null, |s| Value::String(s.to_owned())))
}

/// Cut `permit` to cover exactly `keep` bytes: surplus is released, a shortfall is admitted
/// (nothing changes when the budget refuses it).
fn fit_permit(permit: &mut BytePermit, keep: usize) -> Result<(), ByteAdmissionError> {
    if permit.bytes() < keep {
        permit.grow_to(keep)
    } else {
        if let Ok(surplus) = permit.split(permit.bytes() - keep) {
            drop(surplus);
        }
        Ok(())
    }
}

/// Own `text`, a string moved out of a charged CDP value, as an immutable shared document.
///
/// `rest` is what is left of that value and is freed first. The permit that covered the whole
/// value is cut down to the text's own capacity; surplus is released only after the value's
/// other memory is gone. A capacity above the reservation (the decode bound is an estimate)
/// is admitted afterwards and refused with [`BrowserError::Memory`] when it does not fit.
pub(super) fn admit_text(
    text: String,
    rest: Value,
    mut permit: BytePermit,
) -> Result<AdmittedText, BrowserError> {
    drop(rest);
    if let Err(refused) = fit_permit(&mut permit, text.capacity()) {
        drop(text);
        drop(permit);
        return Err(BrowserError::Memory(refused));
    }
    Ok(AdmittedText::new(text, permit))
}

/// [`admit_text`] for a byte buffer (a capture body) moved out of a charged CDP value: the
/// buffer keeps exactly its own capacity charged, under the permit that metered its reply.
pub(super) fn admit_bytes(
    bytes: Vec<u8>,
    rest: Value,
    mut permit: BytePermit,
) -> Result<AdmittedBytes, BrowserError> {
    drop(rest);
    if let Err(refused) = fit_permit(&mut permit, bytes.capacity()) {
        drop(bytes);
        drop(permit);
        return Err(BrowserError::Memory(refused));
    }
    Ok(AdmittedBytes::new(bytes, permit))
}

/// `Runtime.evaluate` parameters for a by-value main-world evaluation.
fn main_evaluate_params(expression: &str, await_promise: bool, timeout: Duration) -> Value {
    json!({
        "expression": expression,
        "awaitPromise": await_promise,
        "returnByValue": true,
        "timeout": u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
    })
}

/// Decode the base64 `data` member of a command result into bytes that carry their own
/// reservation, made before the output buffer is allocated. The charged response the data
/// borrows from stays alive for the call.
fn decode_data(
    budget: &Arc<ByteBudget>,
    method: &str,
    result: &Value,
) -> Result<AdmittedBytes, BrowserError> {
    let data = result
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| BrowserError::Protocol {
            method: method.to_owned(),
            message: "no data in result".to_owned(),
        })?;
    crate::cdp::decode_admitted_base64(budget, method, data)
}

/// Capture `spec` from `sess`. A full-page capture is as wide as the content, at least
/// `viewport_width` (the layout metrics report the width without the scrollbar).
async fn capture(
    sess: &CdpSession,
    spec: &ShotSpec,
    viewport_width: u32,
) -> Result<AdmittedBytes, BrowserError> {
    let mut params = json!({
        "format": if spec.quality.is_some() { "jpeg" } else { "png" },
        "fromSurface": true,
    });
    if let Some(q) = spec.quality {
        params["quality"] = json!(q.clamp(1, 100));
    }
    if spec.full_page {
        let metrics = sess.send("Page.getLayoutMetrics", json!({})).await?;
        let size = metrics
            .get("cssContentSize")
            .or_else(|| metrics.get("contentSize"))
            .unwrap_or(&Value::Null);
        let edge = |key: &str, least: u32| {
            size.get(key)
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .max(f64::from(least))
                .ceil()
                .clamp(1.0, f64::from(MAX_SHOT_EDGE))
        };
        params["captureBeyondViewport"] = json!(true);
        params["clip"] = json!({
            "x": 0, "y": 0, "width": edge("width", viewport_width), "height": edge("height", 1), "scale": 1,
        });
    }
    let result = sess.send_budgeted("Page.captureScreenshot", params).await?;
    decode_data(sess.client.budget(), "Page.captureScreenshot", result.value())
}

impl CdpContext {
    /// Execute one [`PageOp`] on this context.
    ///
    /// # Errors
    /// [`BrowserError::TargetClosed`] / [`BrowserError::TargetCrashed`] when the context or
    /// its active tab is gone, [`BrowserError::Timeout`] when a command exceeds its bound,
    /// [`BrowserError::Script`] when an evaluated script throws, [`BrowserError::Unsupported`]
    /// for an unknown PDF format or an out-of-range scale, otherwise the
    /// [`BrowserError::Protocol`] error Chromium answered.
    pub(crate) async fn page_op_impl(&mut self, op: PageOp) -> Result<PageOpResult, BrowserError> {
        if self.state.lock().closed {
            return Err(BrowserError::TargetClosed);
        }
        if self.ctl.config.captcha.is_some() && matches!(&op, PageOp::Screenshot(_) | PageOp::PrintToPdf(_)) {
            return Err(BrowserError::Unsupported(
                "binary page captures are unavailable with captcha solving".to_owned(),
            ));
        }
        if self.ctl.config.captcha.is_some() && matches!(&op, PageOp::FlattenedHtml(_)) {
            return Err(BrowserError::Unsupported(
                "flattened serialization is unavailable with captcha solving".to_owned(),
            ));
        }
        let result = match op {
            PageOp::Emulate(em) => self.emulate(em).await.map(|()| PageOpResult::Done),
            PageOp::BlockUrls(patterns) => self.block_urls(patterns).await.map(|()| PageOpResult::Done),
            PageOp::DocumentResponse => self.document_response(),
            PageOp::BeginVirtualRows(spec) => {
                self.begin_virtual_rows(spec).await.map(PageOpResult::VirtualRows)
            }
            PageOp::ReadVirtualRows => self.read_virtual_rows().await.map(PageOpResult::VirtualRows),
            PageOp::VirtualRowsTarget => self.virtual_rows_target().await.map(PageOpResult::Locators),
            PageOp::RestoreVirtualRows => self
                .restore_virtual_rows()
                .await
                .map(PageOpResult::VirtualRowsRestored),
            PageOp::EvaluateScript { script } => self
                .evaluate_main(&script, true, SCRIPT_TIMEOUT)
                .await
                .map(PageOpResult::Json),
            PageOp::Html => self.html().await,
            PageOp::Screenshot(spec) => self.screenshot(&spec).await,
            PageOp::PrintToPdf(spec) => self.print_to_pdf(&spec).await,
            PageOp::Capture(spec) => self.retained_capture(spec).await.map(PageOpResult::Capture),
            PageOp::Download(spec) => self.download(spec).await.map(PageOpResult::Capture),
            PageOp::CaptureProjection => self.capture_projection().await.map(PageOpResult::Projection),
            PageOp::WaitForSelector {
                selector,
                state,
                timeout_ms,
            } => self
                .wait_for_selector(&selector, state, timeout_ms)
                .await
                .map(PageOpResult::Found),
            PageOp::ResolveAll { selector, limit } => self
                .resolve_all(&selector, limit)
                .await
                .map(PageOpResult::Locators),
            PageOp::BlockResources(spec) => {
                self.block_resources(spec).await.map(PageOpResult::BlockInstalled)
            }
            PageOp::FlattenedHtml(spec) => self.flattened_html(spec).await,
            PageOp::MeasureDevice { probe_geolocation } => self
                .measure_device(probe_geolocation)
                .await
                .map(PageOpResult::Device),
        }?;
        self.mask_captcha_page_result(result)
    }

    /// Every live tab session and child-frame session of the context, frames still being set
    /// up included: a frame registers in the state before its setup reads the stored
    /// overrides, so no frame is missed by both that read and this sweep.
    fn sessions(&self) -> Vec<(CdpSession, SessionKind)> {
        let st = self.state.lock();
        st.tabs
            .values()
            .filter(|t| !t.crashed)
            .flat_map(|t| {
                std::iter::once((t.session.clone(), SessionKind::Tab))
                    .chain(t.frames.values().map(|f| (f.session.clone(), SessionKind::Frame)))
            })
            .map(|(session_id, kind)| {
                (
                    CdpSession {
                        client: self.ctl.client.clone(),
                        session_id,
                    },
                    kind,
                )
            })
            .collect()
    }

    /// Is `session_id` still the session of an open tab or child frame? A command that fails
    /// on a session that went away meanwhile (a popup closing mid-sweep) is not an error of
    /// the sweep.
    fn session_alive(&self, session_id: &str) -> bool {
        let st = self.state.lock();
        st.tabs
            .values()
            .any(|t| t.session == session_id || t.frames.values().any(|f| f.session == session_id))
    }

    /// `PageOp::BlockUrls`: store `patterns` for the tabs and frames attached later, then apply
    /// them to every open session.
    async fn block_urls(&self, patterns: Vec<String>) -> Result<(), BrowserError> {
        self.state.lock().overrides.block_urls.clone_from(&patterns);
        for (sess, _) in self.sessions() {
            if let Err(e) = set_blocked_urls(&sess, &patterns).await {
                if self.session_alive(&sess.session_id) {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// `PageOp::BlockResources`: store the list's patterns for the tabs and frames attached
    /// later, install them on every open session and report how many sessions took them. A
    /// session that rejects the list while it is still open is counted, not hidden.
    async fn block_resources(&self, spec: ResourceBlockSpec) -> Result<BlockInstall, BrowserError> {
        let patterns: Vec<String> = spec.entries.into_iter().map(|e| e.pattern).collect();
        self.state.lock().overrides.block_urls.clone_from(&patterns);
        let mut install = BlockInstall {
            patterns: u32::try_from(patterns.len()).unwrap_or(u32::MAX),
            ..BlockInstall::default()
        };
        for (sess, _) in self.sessions() {
            match set_blocked_urls(&sess, &patterns).await {
                Ok(()) => install.sessions_applied = install.sessions_applied.saturating_add(1),
                Err(e) if self.session_alive(&sess.session_id) => {
                    tracing::warn!(error = %e, "block list rejected by an open session");
                    install.sessions_failed = install.sessions_failed.saturating_add(1);
                }
                Err(_) => {}
            }
        }
        Ok(install)
    }

    /// `em` with its `User-Agent` filled in when only `Accept-Language` was asked for: the
    /// override command needs a user agent, and the current one is the context's own
    /// (`fetch.userAgent`, `ContextConfig::user_agent`, else the browser's).
    async fn resolve_emulation(&self, mut em: Emulation) -> Result<Emulation, BrowserError> {
        if em.user_agent.is_none() && em.accept_language.is_some() {
            let ua = match base_user_agent(&self.ctl) {
                Some(ua) => ua.to_owned(),
                None => {
                    let version = self
                        .ctl
                        .client
                        .call("Browser.getVersion", None, json!({}))
                        .await?;
                    version
                        .get("userAgent")
                        .and_then(Value::as_str)
                        .filter(|ua| !ua.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| BrowserError::Protocol {
                            method: "Browser.getVersion".to_owned(),
                            message: "no userAgent".to_owned(),
                        })?
                }
            };
            em.user_agent = Some(ua);
        }
        Ok(em)
    }

    /// `PageOp::Emulate`: the emulation replaces the previous one on every open session and is
    /// stored for the tabs and frames attached later.
    async fn emulate(&self, em: Emulation) -> Result<(), BrowserError> {
        let next = self.resolve_emulation(em).await?;
        // the permission is context-wide, the position override per session
        let had_geolocation = self
            .state
            .lock()
            .overrides
            .emulation
            .as_ref()
            .is_some_and(|e| e.geolocation.is_some());
        if next.geolocation.is_some() {
            self.set_geolocation_permission(true).await?;
        } else if had_geolocation {
            self.set_geolocation_permission(false).await?;
        }
        let prev = {
            let stored = (next != Emulation::default()).then(|| next.clone());
            std::mem::replace(&mut self.state.lock().overrides.emulation, stored)
        };
        for (sess, kind) in self.sessions() {
            if let Err(e) = apply_emulation(&sess, &self.ctl, kind, &next, prev.as_ref(), true).await {
                if self.session_alive(&sess.session_id) {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Grant (`true`) or reset to the default (`false`) the geolocation permission of this
    /// browser context. Without the grant the page cannot read the emulated position.
    async fn set_geolocation_permission(&self, granted: bool) -> Result<(), BrowserError> {
        self.ctl
            .client
            .call(
                "Browser.setPermission",
                None,
                json!({
                    "permission": { "name": "geolocation" },
                    "setting": if granted { "granted" } else { "prompt" },
                    "browserContextId": self.ctl.browser_context_id,
                }),
            )
            .await
            .map(|_| ())
    }

    /// `PageOp::DocumentResponse`: the response of the active tab's latest main-frame document.
    fn document_response(&self) -> Result<PageOpResult, BrowserError> {
        let st = self.state.lock();
        let tab = st.active_tab().ok_or(BrowserError::TargetClosed)?;
        if tab.crashed {
            return Err(BrowserError::TargetCrashed);
        }
        let response = tab.nav_response.clone().unwrap_or_default();
        Ok(PageOpResult::Response {
            status: response.status,
            headers: response.headers,
            content_type: response.content_type,
        })
    }

    /// `Runtime.evaluate` of `expression` in the active tab's main world (the page's own
    /// JavaScript world, unlike [`CdpContext::evaluate_isolated`]) with the by-value result.
    /// `timeout` ends a script that never returns (the V8 execution limit for synchronous
    /// code, the command deadline for a promise that never settles).
    async fn evaluate_main(
        &self,
        expression: &str,
        await_promise: bool,
        timeout: Duration,
    ) -> Result<Value, BrowserError> {
        let (_, sess) = self.session_for(None)?;
        // A plain call: the script's by-value result is returned as an uncharged `Value`, so
        // the transport bounds it at `cdp::METADATA_REPLY_LIMIT` (larger results are refused
        // with `BrowserError::Memory`).
        let v = self
            .ctl
            .client
            .call_with_timeout(
                "Runtime.evaluate",
                Some(&sess.session_id),
                main_evaluate_params(expression, await_promise, timeout),
                timeout + Duration::from_secs(1),
            )
            .await?;
        main_world_result(&v)
    }

    /// `Runtime.evaluate` in the main world returning the whole response still charged to the
    /// byte budget, for results the caller retains (the document HTML).
    async fn evaluate_main_charged(
        &self,
        expression: &str,
        await_promise: bool,
        timeout: Duration,
    ) -> Result<Budgeted<Value>, BrowserError> {
        let (_, sess) = self.session_for(None)?;
        self.ctl
            .client
            .call_budgeted_with_timeout(
                "Runtime.evaluate",
                Some(&sess.session_id),
                main_evaluate_params(expression, await_promise, timeout),
                timeout + Duration::from_secs(1),
            )
            .await
    }

    /// Evaluate `script` (awaiting a returned promise) in the main world and keep the whole
    /// reply charged: the transport reserves the reply before its bytes are allocated, and the
    /// caller moves the parts it retains out under that same reservation. A thrown value
    /// becomes [`BrowserError::Script`].
    pub(super) async fn evaluate_script_charged(
        &self,
        script: &str,
    ) -> Result<Budgeted<Value>, BrowserError> {
        let reply = self.evaluate_main_charged(script, true, SCRIPT_TIMEOUT).await?;
        if let Some(details) = reply.value().get("exceptionDetails") {
            return Err(BrowserError::Script(exception_message(details)));
        }
        Ok(reply)
    }

    /// `PageOp::Html`: the serialized document is moved out of the charged response, not
    /// copied, and keeps exactly its own reservation.
    async fn html(&self) -> Result<PageOpResult, BrowserError> {
        let mut reply = self
            .evaluate_main_charged(HTML_SCRIPT, false, SCRIPT_TIMEOUT)
            .await?;
        if let Some(details) = reply.value().get("exceptionDetails") {
            return Err(BrowserError::Script(exception_message(details)));
        }
        let shape = || BrowserError::Script("document serialization returned an unexpected shape".to_owned());
        let Some(Value::Object(document)) = reply.value_mut().pointer_mut("/result/value") else {
            return Err(shape());
        };
        let html = match document.get_mut("html") {
            Some(Value::String(html)) => std::mem::take(html),
            _ => return Err(shape()),
        };
        let url = match document.get_mut("url") {
            Some(Value::String(url)) => std::mem::take(url),
            _ => return Err(shape()),
        };
        let (response, permit) = reply.into_parts();
        let html = admit_text(html, response, permit)?;
        Ok(PageOpResult::Html { html, url })
    }

    /// `PageOp::FlattenedHtml`: the document serialized with open shadow roots and readable
    /// iframes folded in. The page is only read; nothing in it is tagged or changed, so the
    /// element identity actions rely on is the same before and after.
    async fn flattened_html(&self, spec: FlattenSpec) -> Result<PageOpResult, BrowserError> {
        let params = json!({
            "shadowDom": spec.shadow_dom,
            "frames": spec.frames,
            "maxFrames": spec.max_frames.clamp(1, FlattenSpec::MAX_FRAMES_LIMIT),
            "maxDepth": FlattenSpec::MAX_DEPTH,
        });
        let script = format!("({FLATTEN_SCRIPT})({params})");
        let mut reply = self.evaluate_main_charged(&script, false, SCRIPT_TIMEOUT).await?;
        if let Some(details) = reply.value().get("exceptionDetails") {
            return Err(BrowserError::Script(exception_message(details)));
        }
        let shape =
            || BrowserError::Script("flattened serialization returned an unexpected shape".to_owned());
        let Some(Value::Object(document)) = reply.value_mut().pointer_mut("/result/value") else {
            return Err(shape());
        };
        let html = match document.get_mut("html") {
            Some(Value::String(html)) => std::mem::take(html),
            _ => return Err(shape()),
        };
        let url = match document.get_mut("url") {
            Some(Value::String(url)) => std::mem::take(url),
            _ => return Err(shape()),
        };
        let frames_omitted = document
            .get("omitted")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(shape)?;
        let frames: Vec<FrameProvenance> =
            serde_json::from_value(document.get_mut("frames").map(Value::take).ok_or_else(shape)?)
                .map_err(|_| shape())?;
        let (response, permit) = reply.into_parts();
        let html = admit_text(html, response, permit)?;
        Ok(PageOpResult::Flattened(FlattenedDocument {
            html,
            url,
            frames,
            frames_omitted,
        }))
    }

    /// `PageOp::MeasureDevice`: what the active tab's page reports about its device.
    async fn measure_device(&self, probe_geolocation: bool) -> Result<DeviceMeasurement, BrowserError> {
        let script = format!("({MEASURE_SCRIPT})({probe_geolocation})");
        let value = self.evaluate_main(&script, true, SCRIPT_TIMEOUT).await?;
        parse_measurement(&value)
    }

    /// Measure every [`DevicePreset`] on the active tab and restore the context's own
    /// emulation afterwards. `chromium_version` and `pinned` describe the running build; the
    /// entries are what the page itself reported under each preset, compared with the request
    /// and with the device class.
    ///
    /// # Errors
    /// The first protocol or script error of a preset; the emulation is restored first.
    pub async fn measure_device_matrix(
        &self,
        chromium_version: &str,
        pinned: bool,
    ) -> Result<DeviceMatrixV1, BrowserError> {
        let locale = self.ctl.config.locale.clone();
        let mut entries = Vec::with_capacity(DevicePreset::ALL.len());
        let mut failure = None;
        for preset in DevicePreset::ALL {
            let requested = preset.emulation(chromium_version, &locale);
            let measured = async {
                self.emulate(requested.clone()).await?;
                self.measure_device(false).await
            }
            .await;
            match measured {
                Ok(measured) => {
                    entries.push(DeviceMatrixEntryV1::check(
                        preset,
                        requested,
                        measured,
                        chromium_version,
                    ));
                }
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        let restored = self.emulate(Emulation::default()).await;
        if let Some(e) = failure {
            return Err(e);
        }
        restored?;
        Ok(DeviceMatrixV1::new(
            DeviceBuildV1 {
                chromium_version: chromium_version.to_owned(),
                pinned,
            },
            entries,
        ))
    }

    /// `PageOp::Screenshot`: the viewport override applies for this capture only.
    async fn screenshot(&self, spec: &ShotSpec) -> Result<PageOpResult, BrowserError> {
        let (_, sess) = self.session_for(None)?;
        let emulation = self.state.lock().overrides.emulation.clone().unwrap_or_default();
        let Some(viewport) = spec.viewport else {
            let width = viewport_of(&self.ctl, &emulation, None).0;
            let bytes = capture(&sess, spec, width).await?;
            return Ok(shot_result(spec, bytes));
        };
        sess.send(
            "Emulation.setDeviceMetricsOverride",
            metrics_params(&self.ctl, &emulation, Some(viewport)),
        )
        .await?;
        let shot = capture(&sess, spec, viewport.0).await;
        let restored = sess
            .send(
                "Emulation.setDeviceMetricsOverride",
                metrics_params(&self.ctl, &emulation, None),
            )
            .await
            .map(|_| ());
        match (shot, restored) {
            (Ok(bytes), Ok(())) => Ok(shot_result(spec, bytes)),
            (Err(e), _) | (Ok(_), Err(e)) => Err(e),
        }
    }

    /// `PageOp::PrintToPdf`.
    async fn print_to_pdf(&self, spec: &PdfSpec) -> Result<PageOpResult, BrowserError> {
        let (width, height) = paper_inches(spec.format.as_deref())?;
        if !(0.1..=2.0).contains(&spec.scale) {
            return Err(BrowserError::Unsupported(format!(
                "pdf scale {} outside 0.1..=2.0",
                spec.scale
            )));
        }
        let scale = (f64::from(spec.scale) * 1000.0).round() / 1000.0;
        let (_, sess) = self.session_for(None)?;
        let result = sess
            .send_budgeted(
                "Page.printToPDF",
                json!({
                    "landscape": spec.landscape,
                    "printBackground": true,
                    "scale": scale,
                    "paperWidth": width,
                    "paperHeight": height,
                }),
            )
            .await?;
        Ok(PageOpResult::Bytes {
            bytes: decode_data(self.ctl.client.budget(), "Page.printToPDF", result.value())?,
            content_type: "application/pdf",
        })
    }

    /// Probe the first CSS match at most every 100 ms, using the narrow `SelectorState`
    /// visibility contract. A replaced document or busy page is retried within the budget;
    /// invalid CSS propagates as a typed script error.
    async fn wait_for_selector(
        &self,
        selector: &str,
        state: SelectorState,
        timeout_ms: u32,
    ) -> Result<bool, BrowserError> {
        let literal =
            serde_json::to_string(selector).map_err(|e| BrowserError::Script(format!("selector: {e}")))?;
        let condition = match state {
            SelectorState::Attached => "el !== null",
            SelectorState::Detached => "el === null",
            SelectorState::Visible => "visible",
            SelectorState::Hidden => "!visible",
            _ => return Err(BrowserError::Unsupported("selector wait state".to_owned())),
        };
        let visibility = if matches!(state, SelectorState::Visible | SelectorState::Hidden) {
            "let visible = false;
             if (el !== null) {
               const box = el.getBoundingClientRect();
               const style = getComputedStyle(el);
               visible = box.width > 0 && box.height > 0 &&
                 style.visibility !== 'hidden' && style.visibility !== 'collapse';
             }"
        } else {
            ""
        };
        // Only JSON-escaped selector data enters this fixed script, never caller code.
        let probe = format!(
            "(() => {{ const el = document.querySelector({literal}); {visibility} return {condition}; }})()"
        );
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.evaluate_main(&probe, false, remaining.max(MIN_PROBE)).await {
                Ok(Value::Bool(true)) => return Ok(true),
                Ok(_) | Err(BrowserError::Timeout(_)) => {}
                Err(BrowserError::Protocol { message, .. })
                    if message.to_ascii_lowercase().contains("context") => {}
                Err(e) => return Err(e),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            tokio::time::sleep(POLL_INTERVAL.min(remaining)).await;
        }
    }

    /// `PageOp::ResolveAll`: locators of the elements matching the CSS `selector` in the main
    /// document, built as `resolve_selector` builds one (tab, main frame, backend node id,
    /// the tab's current epoch). A selector the browser cannot parse matches nothing, as in
    /// `resolve_selector`.
    pub(super) async fn resolve_all(
        &self,
        selector: &str,
        limit: u32,
    ) -> Result<Vec<RuntimeLocator>, BrowserError> {
        let (target_id, sess) = self.session_for(None)?;
        let (main_frame, epoch) = {
            let st = self.state.lock();
            let t = st.tabs.get(&target_id).ok_or(BrowserError::TargetClosed)?;
            (t.main_frame.clone(), t.epoch)
        };
        let selector = selector.trim();
        if selector.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let root = sess.send("DOM.getDocument", json!({ "depth": 0 })).await?;
        let Some(root_id) = root
            .get("root")
            .and_then(|r| r.get("nodeId"))
            .and_then(Value::as_i64)
        else {
            return Ok(Vec::new());
        };
        let found = match sess
            .send(
                "DOM.querySelectorAll",
                json!({ "nodeId": root_id, "selector": selector }),
            )
            .await
        {
            Ok(v) => v,
            Err(BrowserError::Protocol { .. }) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let ids: Vec<i64> = found
            .get("nodeIds")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_i64).filter(|id| *id != 0).collect())
            .unwrap_or_default();
        let take = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut locators = Vec::with_capacity(ids.len().min(take));
        for id in ids.into_iter().take(take) {
            if let Some((_, backend, _)) = describe(&sess, id).await {
                locators.push(RuntimeLocator {
                    tab: TabId(target_id.clone()),
                    frame: FrameId(main_frame.clone()),
                    backend_node_id: BackendNodeId(backend),
                    object_id: None,
                    ax_node_id: None,
                    epoch,
                });
            }
        }
        // keep `current_epoch()` fresh for the caller's epoch policy
        let _ = self.poll_counters(Some(&target_id)).await;
        Ok(locators)
    }
}

/// The result of a finished capture.
fn shot_result(spec: &ShotSpec, bytes: AdmittedBytes) -> PageOpResult {
    PageOpResult::Bytes {
        bytes,
        content_type: if spec.quality.is_some() {
            "image/jpeg"
        } else {
            "image/png"
        },
    }
}

/// The [`DeviceMeasurement`] a measurement script answered.
///
/// # Errors
/// [`BrowserError::Script`] when a member is missing or out of range.
fn parse_measurement(v: &Value) -> Result<DeviceMeasurement, BrowserError> {
    let shape = || BrowserError::Script("device measurement returned an unexpected shape".to_owned());
    let unsigned = |key: &str| -> Result<u32, BrowserError> {
        v.get(key)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(shape)
    };
    let text = |key: &str| -> Result<String, BrowserError> {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(shape)
    };
    let geolocation = match v.get("geo") {
        None | Some(Value::Null) => None,
        Some(geo) => {
            let signed = |key: &str| {
                geo.get(key)
                    .and_then(Value::as_i64)
                    .and_then(|n| i32::try_from(n).ok())
            };
            let accuracy = geo
                .get("accuracyM")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .map(|n| n.clamp(1, GeoPosition::MAX_ACCURACY_M));
            match (signed("latitudeE6"), signed("longitudeE6"), accuracy) {
                (Some(lat), Some(lon), Some(acc)) => GeoPosition::new(lat, lon, acc).ok(),
                _ => None,
            }
        }
    };
    Ok(DeviceMeasurement {
        viewport: (unsigned("width")?, unsigned("height")?),
        screen: (unsigned("screenWidth")?, unsigned("screenHeight")?),
        device_pixel_ratio_milli: unsigned("pixelRatioMilli")?,
        user_agent: text("userAgent")?,
        language: text("language")?,
        time_zone: text("timeZone")?,
        max_touch_points: unsigned("maxTouchPoints")?,
        pointer_coarse: v
            .get("pointerCoarse")
            .and_then(Value::as_bool)
            .ok_or_else(shape)?,
        geolocation,
        geolocation_error: v.get("geoError").and_then(Value::as_str).map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn paper_sizes_cover_the_named_formats() {
        assert_eq!(paper_inches(None).unwrap(), (8.5, 11.0));
        assert_eq!(paper_inches(Some("a4")).unwrap(), (8.27, 11.7));
        assert_eq!(paper_inches(Some("Tabloid")).unwrap(), (11.0, 17.0));
        assert_eq!(paper_inches(Some("LEDGER")).unwrap(), (17.0, 11.0));
        for name in ["Letter", "Legal", "A0", "A1", "A2", "A3", "A4", "A5", "A6"] {
            let (w, h) = paper_inches(Some(name)).unwrap();
            assert!(w > 0.0 && h > 0.0, "{name}");
        }
        assert!(matches!(
            paper_inches(Some("A7")),
            Err(BrowserError::Unsupported(_))
        ));
        assert!(matches!(
            paper_inches(Some("")),
            Err(BrowserError::Unsupported(_))
        ));
    }

    #[test]
    fn thrown_values_become_script_errors_without_the_stack() {
        let error = json!({ "exceptionDetails": { "text": "Uncaught", "exception": {
            "type": "object", "description": "Error: boom\n    at <anonymous>:1:7" } } });
        match main_world_result(&error) {
            Err(BrowserError::Script(m)) => assert_eq!(m, "Error: boom"),
            other => panic!("{other:?}"),
        }
        let primitive = json!({ "exceptionDetails": { "text": "Uncaught",
            "exception": { "type": "string", "value": "plain" } } });
        match main_world_result(&primitive) {
            Err(BrowserError::Script(m)) => assert_eq!(m, "plain"),
            other => panic!("{other:?}"),
        }
        let bare = json!({ "exceptionDetails": { "text": "Uncaught" } });
        match main_world_result(&bare) {
            Err(BrowserError::Script(m)) => assert_eq!(m, "Uncaught"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn evaluation_results_keep_json_and_name_unserializable_values() {
        let value = json!({ "result": { "type": "object", "value": { "a": [1, 2] } } });
        assert_eq!(main_world_result(&value).unwrap(), json!({ "a": [1, 2] }));
        let undefined = json!({ "result": { "type": "undefined" } });
        assert_eq!(main_world_result(&undefined).unwrap(), Value::Null);
        let nan = json!({ "result": { "type": "number", "unserializableValue": "NaN" } });
        assert_eq!(main_world_result(&nan).unwrap(), json!("NaN"));
    }

    #[test]
    fn capture_data_decodes_or_reports_the_method() {
        let budget = Arc::new(ByteBudget::new(1 << 20));
        let decoded = decode_data(&budget, "capture", &json!({ "data": "AQID" })).unwrap();
        assert_eq!(decoded.as_slice(), [1, 2, 3]);
        assert!(budget.used() >= 3, "decoded bytes stay charged while held");
        drop(decoded);
        assert_eq!(budget.used(), 0);
        for bad in [json!({}), json!({ "data": "***" })] {
            match decode_data(&budget, "capture", &bad) {
                Err(BrowserError::Protocol { method, .. }) => assert_eq!(method, "capture"),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(budget.used(), 0, "a refused decode releases its reservation");
    }

    #[test]
    fn oversized_capture_is_refused_before_the_decode_buffer_exists() {
        let budget = Arc::new(ByteBudget::new(64));
        let data = "A".repeat(4096);
        match decode_data(&budget, "capture", &json!({ "data": data })) {
            Err(BrowserError::Memory(refused)) => assert!(refused.exceeds_budget()),
            other => panic!("{other:?}"),
        }
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn admitted_text_keeps_only_its_own_capacity_charged() {
        let budget = Arc::new(ByteBudget::new(1 << 20));
        let permit = budget.try_reserve(10_000).unwrap();
        let text = String::from("<html></html>");
        let capacity = text.capacity();
        let admitted = admit_text(text, json!({ "ballast": "x".repeat(1000) }), permit).unwrap();
        assert_eq!(budget.used(), capacity);
        let shared = admitted.clone();
        drop(admitted);
        assert_eq!(budget.used(), capacity, "clones share one reservation");
        drop(shared);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn admitted_text_beyond_its_reservation_is_refused_and_released() {
        let budget = Arc::new(ByteBudget::new(16));
        let permit = budget.try_reserve(1).unwrap();
        let text = "x".repeat(64);
        assert!(matches!(
            admit_text(text, Value::Null, permit),
            Err(BrowserError::Memory(_))
        ));
        assert_eq!(budget.used(), 0);
    }
}
