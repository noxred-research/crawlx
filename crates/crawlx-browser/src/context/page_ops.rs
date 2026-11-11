//! Caller-driven page operations (`BrowserContext::page_op`): the emulation,
//! request blocking, script evaluation, serialization, screenshot and PDF operations the
//! scrape engine needs beyond the journaled `BrowserAction` vocabulary.
//!
//! `BlockUrls` and `Emulate` are context-wide: the value is stored in `State::overrides`,
//! applied to every open tab and child-frame session, and re-applied by `setup_tab` /
//! `setup_frame` ([`apply_overrides`]) to the tabs and frames attached later (popups, new
//! iframes). Every other operation targets the active tab. Script-visible reads (`Html`,
//! `EvaluateScript`, `WaitForSelector`) run in the page's main world with `Runtime.evaluate`,
//! which needs neither `Runtime.enable` nor the isolated world, so they work under every
//! launch profile. Every command is bounded by an explicit timeout.

use super::selector::describe;
use super::state::State;
use super::{CdpContext, Ctl};
use crate::cdp::CdpSession;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use crawlx_core::browser::BrowserError;
use crawlx_core::ids::{BackendNodeId, FrameId, TabId};
use crawlx_core::observation::RuntimeLocator;
use crawlx_core::page_op::{Emulation, PageOp, PageOpResult, PdfSpec, SelectorState, ShotSpec};
use parking_lot::Mutex;
use serde_json::{json, Value};
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

/// `Emulation.setDeviceMetricsOverride` parameters for [`viewport_of`] at scale 1, mobile per
/// the emulation.
fn metrics_params(ctl: &Ctl, em: &Emulation, viewport: Option<(u32, u32)>) -> Value {
    let (width, height) = viewport_of(ctl, em, viewport);
    json!({ "width": width, "height": height, "deviceScaleFactor": 1, "mobile": em.mobile })
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
    if kind == SessionKind::Tab && (next.viewport.is_some() || next.mobile || prev.is_some()) {
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

/// Decode the base64 `data` member of a command result.
fn decode_data(method: &str, result: &Value) -> Result<Vec<u8>, BrowserError> {
    let data = result
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| BrowserError::Protocol {
            method: method.to_owned(),
            message: "no data in result".to_owned(),
        })?;
    STANDARD.decode(data).map_err(|e| BrowserError::Protocol {
        method: method.to_owned(),
        message: e.to_string(),
    })
}

/// Capture `spec` from `sess`. A full-page capture is as wide as the content, at least
/// `viewport_width` (the layout metrics report the width without the scrollbar).
async fn capture(sess: &CdpSession, spec: &ShotSpec, viewport_width: u32) -> Result<Vec<u8>, BrowserError> {
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
    let result = sess.send("Page.captureScreenshot", params).await?;
    decode_data("Page.captureScreenshot", &result)
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
        let limit_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let v = self
            .ctl
            .client
            .call_with_timeout(
                "Runtime.evaluate",
                Some(&sess.session_id),
                json!({
                    "expression": expression,
                    "awaitPromise": await_promise,
                    "returnByValue": true,
                    "timeout": limit_ms,
                }),
                timeout + Duration::from_secs(1),
            )
            .await?;
        main_world_result(&v)
    }

    /// `PageOp::Html`.
    async fn html(&self) -> Result<PageOpResult, BrowserError> {
        let v = self.evaluate_main(HTML_SCRIPT, false, SCRIPT_TIMEOUT).await?;
        let field = |key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
        match (field("html"), field("url")) {
            (Some(html), Some(url)) => Ok(PageOpResult::Html { html, url }),
            _ => Err(BrowserError::Script(
                "document serialization returned an unexpected shape".to_owned(),
            )),
        }
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
            .send(
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
            bytes: decode_data("Page.printToPDF", &result)?,
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
fn shot_result(spec: &ShotSpec, bytes: Vec<u8>) -> PageOpResult {
    PageOpResult::Bytes {
        bytes,
        content_type: if spec.quality.is_some() {
            "image/jpeg"
        } else {
            "image/png"
        },
    }
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
        assert_eq!(
            decode_data("capture", &json!({ "data": "AQID" })).unwrap(),
            vec![1, 2, 3]
        );
        for bad in [json!({}), json!({ "data": "***" })] {
            match decode_data("capture", &bad) {
                Err(BrowserError::Protocol { method, .. }) => assert_eq!(method, "capture"),
                other => panic!("{other:?}"),
            }
        }
    }
}
