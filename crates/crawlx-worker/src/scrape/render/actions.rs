//! The caller's `actions[]` (compatibility API): `wait`, `click`, `write`, `press`, `scroll`,
//! `screenshot`, `scrape`, `executeJavascript` and `pdf`, executed in order on one page.
//!
//! Actions that act on the page as a user would (`click`, `write`, `press`, `scroll`) are
//! native input proposed under the `explicit_actions` strategy: observed, revalidated,
//! adjudicated by the safety kernel and journaled by the Session Actor exactly like an
//! exploration action ([`crate::driven`]). Typed text is user data: the journal records the
//! action kind and the number of characters, never the text. The other actions read or wait
//! and cannot change server state; each leaves a `scrape.action {index, type}` audit event.

use super::{render_error, ActionOutputs, RenderError, Shot};
use crate::driven::{Attribution, DriveFailure, Driver};
use crate::error::SessionError;
use crawlx_browser::input::key_def;
use crawlx_core::action::{BrowserAction, KeyChord, Modifiers, PointerButton, ScrollDelta};
use crawlx_core::dom_ops::{VirtualRowsReport, VirtualRowsRestoration, VirtualRowsSpec, VirtualRowsStop};
use crawlx_core::hash::Digest;
use crawlx_core::identity::InputClass;
use crawlx_core::ids::BackendNodeId;
use crawlx_core::observation::{LiveTargetFacts, ObservationBundle, Revalidation, RuntimeLocator};
use crawlx_core::page_op::{PageOp, PageOpResult, PdfSpec, SelectorState, ShotSpec};
use crawlx_core::scrape::{ActionScrape, JavascriptReturn, ScrapeAction, ScrollDirection};
use crawlx_core::BrowserError;
use crawlx_fetch::DENIED_HEADER;
use crawlx_observe::spec;
use std::time::Duration;

/// `ActionProposal.strategy` of every caller action.
pub const EXPLICIT_ACTIONS_STRATEGY: &str = "explicit_actions";
/// Version of [`EXPLICIT_ACTIONS_STRATEGY`].
const STRATEGY_VERSION: u32 = 1;
/// Longest a `wait{selector}` action waits for the element.
pub const WAIT_SELECTOR_MS: u32 = 30_000;
/// One probe of a `wait{selector}`: the actor is busy for this long at most, so a render that
/// times out or is cancelled is not held up by a long wait.
const WAIT_PROBE_MS: u32 = 500;
/// Most elements one `click{all}` action addresses.
pub const MAX_CLICK_TARGETS: u32 = 10_000;
/// Domain of the digest that identifies what an action addressed.
const TARGET_DOMAIN: &str = "crawlx/worker/scrape-target";
/// Domain of the digest an `executeJavascript` event records instead of the script.
const SCRIPT_DOMAIN: &str = "crawlx/worker/scrape-script";

/// Runs the actions of one scrape through its Session Actor.
pub(super) struct ActionRunner<'a> {
    driver: Driver<'a>,
    outputs: ActionOutputs,
    virtual_bytes_remaining: usize,
}

impl<'a> ActionRunner<'a> {
    pub(super) fn new(driver: Driver<'a>, virtual_bytes_remaining: usize) -> Self {
        Self {
            driver,
            outputs: ActionOutputs {
                virtual_rows_max_bytes: Some(virtual_bytes_remaining),
                ..ActionOutputs::default()
            },
            virtual_bytes_remaining,
        }
    }

    /// Run `actions` in order and return what they produced.
    ///
    /// # Errors
    /// The first action that fails ends the run with [`RenderError::Action`] (`reason`:
    /// `selector_not_found`, `selector_timeout`, `not_actionable`, `denied`, `unknown_key`,
    /// `script_error`, `invalid`, `failed`, `stale_epoch`, `identity_changed`), or with the
    /// error of the browser (an egress-denied or failed navigation the action caused).
    pub(super) async fn run(mut self, actions: &[ScrapeAction]) -> Result<ActionOutputs, RenderError> {
        for (index, action) in actions.iter().enumerate() {
            self.step(index, action).await?;
        }
        Ok(self.outputs)
    }

    async fn step(&mut self, index: usize, action: &ScrapeAction) -> Result<(), RenderError> {
        match action {
            ScrapeAction::Wait {
                milliseconds: Some(ms),
                selector: None,
                state: SelectorState::Attached,
            } => {
                self.note(index, action, None).await;
                tokio::time::sleep(Duration::from_millis(u64::from(*ms))).await;
                Ok(())
            }
            ScrapeAction::Wait {
                milliseconds: None,
                selector: Some(selector),
                state,
            } => {
                self.note(index, action, None).await;
                self.wait_for_selector(index, action, selector, *state).await
            }
            ScrapeAction::Wait { .. } => Err(fail(index, action, "invalid")),
            ScrapeAction::Click { selector, all } => self.click(index, action, selector, *all).await,
            ScrapeAction::Write { text } => self.write(index, action, text).await,
            ScrapeAction::Press { key } => self.press(index, action, key).await,
            ScrapeAction::Scroll { direction, selector } => {
                self.scroll(index, action, *direction, selector.as_deref(), None)
                    .await
            }
            ScrapeAction::Screenshot {
                full_page,
                quality,
                viewport,
            } => {
                self.note(index, action, None).await;
                let spec = ShotSpec {
                    full_page: *full_page,
                    quality: *quality,
                    viewport: viewport.map(|v| (v.width, v.height)),
                };
                let shot = shot_of(self.page_op(PageOp::Screenshot(spec)).await?)?;
                self.outputs.screenshots.push(shot);
                Ok(())
            }
            ScrapeAction::Scrape => {
                self.note(index, action, None).await;
                match self.page_op(PageOp::Html).await? {
                    PageOpResult::Html { html, url } => {
                        self.outputs.scrapes.push(ActionScrape { url, html });
                        Ok(())
                    }
                    _ => Err(unexpected("html")),
                }
            }
            ScrapeAction::CollectVirtualRows { spec } => {
                self.note(index, action, None).await;
                self.collect_virtual_rows(index, action, spec).await
            }
            ScrapeAction::ExecuteJavascript { script } => {
                let facts = serde_json::json!({
                    "scriptLength": script.len(),
                    "scriptDigest": Digest::of(SCRIPT_DOMAIN, script.as_bytes()).to_hex(),
                });
                self.note(index, action, Some(facts)).await;
                let result = self
                    .driver
                    .handle
                    .page_op(PageOp::EvaluateScript {
                        script: script.clone(),
                    })
                    .await;
                match result {
                    Ok(PageOpResult::Json(value)) => {
                        self.outputs.javascript_returns.push(JavascriptReturn {
                            kind: json_type(&value).to_owned(),
                            value,
                        });
                        Ok(())
                    }
                    Ok(_) => Err(unexpected("evaluate_script")),
                    Err(SessionError::Browser(BrowserError::Script(_))) => {
                        Err(fail(index, action, "script_error"))
                    }
                    Err(e) => Err(render_error(e)),
                }
            }
            ScrapeAction::Pdf {
                format,
                landscape,
                scale,
            } => {
                self.note(index, action, None).await;
                let spec = PdfSpec {
                    format: format.clone(),
                    landscape: *landscape,
                    scale: scale.unwrap_or(1.0),
                };
                let result = self.driver.handle.page_op(PageOp::PrintToPdf(spec)).await;
                match result {
                    Ok(done) => {
                        let pdf = shot_of(done)?;
                        self.outputs.pdfs.push(pdf);
                        Ok(())
                    }
                    // an unknown paper format or a scale outside 0.1..=2.0
                    Err(SessionError::Browser(BrowserError::Unsupported(_))) => {
                        Err(fail(index, action, "invalid"))
                    }
                    Err(e) => Err(render_error(e)),
                }
            }
        }
    }

    /// `wait{selector,state}`: probe until the state holds, at most [`WAIT_SELECTOR_MS`]. Each
    /// probe is a short page operation ([`WAIT_PROBE_MS`]) rather than one long one, because
    /// the actor serves one command at a time and a long command would delay the close of the
    /// session after a timeout or a cancellation.
    async fn wait_for_selector(
        &self,
        index: usize,
        action: &ScrapeAction,
        selector: &str,
        state: SelectorState,
    ) -> Result<(), RenderError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(u64::from(WAIT_SELECTOR_MS));
        loop {
            let probe = PageOp::WaitForSelector {
                selector: selector.to_owned(),
                state,
                timeout_ms: WAIT_PROBE_MS,
            };
            let found = match self.driver.handle.page_op(probe).await {
                Ok(result) => result,
                // a selector the page cannot parse
                Err(SessionError::Browser(BrowserError::Script(_))) => {
                    return Err(fail(index, action, "invalid_selector"));
                }
                Err(e) => return Err(render_error(e)),
            };
            match found {
                PageOpResult::Found(true) => return Ok(()),
                PageOpResult::Found(false) if tokio::time::Instant::now() >= deadline => {
                    return Err(fail(index, action, "selector_timeout"));
                }
                PageOpResult::Found(false) => {}
                _ => return Err(unexpected("wait_for_selector")),
            }
        }
    }

    /// `click`: the first match, or with `all` every element the selector matched when the
    /// action began. Each click is its own observed, adjudicated, journaled action; an element
    /// that left the document meanwhile is skipped, and with `all` so is one that is not
    /// actionable (hidden, disabled, covered) as long as some match was clicked.
    async fn click(
        &self,
        index: usize,
        action: &ScrapeAction,
        selector: &str,
        all: bool,
    ) -> Result<(), RenderError> {
        let first = self.resolve(selector, MAX_CLICK_TARGETS).await?;
        let take = if all { first.len() } else { 1 };
        let targets: Vec<BackendNodeId> = first.iter().take(take).map(|l| l.backend_node_id).collect();
        if targets.is_empty() {
            return Err(fail(index, action, "selector_not_found"));
        }
        let mut clicked = 0_usize;
        for id in &targets {
            let bundle = self.observe().await?;
            // a click moves the epoch: find the element again by its node id
            let current = self.resolve(selector, MAX_CLICK_TARGETS).await?;
            let Some(target) = current.into_iter().find(|l| l.backend_node_id == *id) else {
                continue;
            };
            let live = match self
                .driver
                .handle
                .revalidate(target.clone())
                .await
                .map_err(render_error)?
            {
                Revalidation::Actionable { live } => live,
                _ if all => continue,
                _ => return Err(fail(index, action, "not_actionable")),
            };
            let who = self.attribution(index, action, selector.as_bytes(), InputClass::none(), None);
            self.driver
                .drive(
                    &bundle,
                    BrowserAction::Click {
                        target,
                        button: PointerButton::Left,
                        modifiers: Modifiers::default(),
                    },
                    live,
                    who,
                )
                .await
                .map_err(|e| drive_error(index, action, e))?;
            clicked += 1;
        }
        if clicked == 0 {
            return Err(fail(index, action, "not_actionable"));
        }
        self.check_navigation().await
    }

    /// `write`: the characters of `text` as native key presses into the focused element
    /// (`\n` is Enter, `\t` is Tab).
    async fn write(&self, index: usize, action: &ScrapeAction, text: &str) -> Result<(), RenderError> {
        let sequence: Vec<KeyChord> = text.chars().map(typed_chord).collect();
        if sequence.is_empty() {
            return Ok(());
        }
        let bundle = self.observe().await?;
        let who = self.attribution(
            index,
            action,
            b"keyboard",
            InputClass::new("text", "explicit"),
            Some(format!("{} chars", sequence.len())),
        );
        let facts = page_facts(&bundle);
        self.driver
            .drive(&bundle, BrowserAction::Keys { sequence }, facts, who)
            .await
            .map_err(|e| drive_error(index, action, e))?;
        self.check_navigation().await
    }

    /// `press`: one key, or a chord such as `Control+A`, on the focused element.
    async fn press(&self, index: usize, action: &ScrapeAction, key: &str) -> Result<(), RenderError> {
        let chord = parse_chord(key).ok_or_else(|| fail(index, action, "unknown_key"))?;
        let bundle = self.observe().await?;
        let who = self.attribution(index, action, b"keyboard", InputClass::none(), None);
        let facts = page_facts(&bundle);
        self.driver
            .drive(
                &bundle,
                BrowserAction::Keys {
                    sequence: vec![chord],
                },
                facts,
                who,
            )
            .await
            .map_err(|e| drive_error(index, action, e))?;
        self.check_navigation().await
    }

    /// `scroll`: one viewport height up or down, over the page or over the element `selector`
    /// matches.
    async fn scroll(
        &self,
        index: usize,
        action: &ScrapeAction,
        direction: ScrollDirection,
        selector: Option<&str>,
        step: Option<f64>,
    ) -> Result<(), RenderError> {
        let bundle = self.observe().await?;
        let (container, facts, element) = match selector {
            Some(sel) => {
                let targets = if matches!(action, ScrapeAction::CollectVirtualRows { .. }) {
                    match self.page_op(PageOp::VirtualRowsTarget).await? {
                        PageOpResult::Locators(targets) => targets,
                        _ => return Err(unexpected("virtual_rows_target")),
                    }
                } else {
                    self.resolve(sel, 1).await?
                };
                let target = targets
                    .into_iter()
                    .next()
                    .ok_or_else(|| fail(index, action, "selector_not_found"))?;
                let live = match self
                    .driver
                    .handle
                    .revalidate(target.clone())
                    .await
                    .map_err(render_error)?
                {
                    Revalidation::Actionable { live } => live,
                    _ => return Err(fail(index, action, "not_actionable")),
                };
                (Some(target), live, sel.as_bytes())
            }
            None => (None, page_facts(&bundle), b"page".as_slice()),
        };
        let step = step.unwrap_or_else(|| f64::from(bundle.viewport.height));
        let dy = match direction {
            ScrollDirection::Down => step,
            ScrollDirection::Up => -step,
        };
        let who = self.attribution(index, action, element, InputClass::none(), None);
        self.driver
            .drive(
                &bundle,
                BrowserAction::Scroll {
                    container,
                    delta: ScrollDelta { dx: 0.0, dy },
                },
                facts,
                who,
            )
            .await
            .map_err(|e| drive_error(index, action, e))
    }

    /// The browser pin owns cleanup even if cancellation drops this future between commands.
    async fn collect_virtual_rows(
        &mut self,
        index: usize,
        action: &ScrapeAction,
        spec: &VirtualRowsSpec,
    ) -> Result<(), RenderError> {
        let mut spec = spec.clone();
        spec.max_bytes = spec
            .max_bytes
            .min(u32::try_from(self.virtual_bytes_remaining).unwrap_or(u32::MAX));
        spec.validate()
            .map_err(|_| fail(index, action, "remaining_byte_allowance_exhausted"))?;
        let original_settle = self.driver.settle;
        self.driver.settle = crawlx_core::observation::QuiescencePolicy {
            mutation_idle_window_ms: u64::from(spec.settle_ms),
            network_idle_window_ms: u64::from(spec.settle_ms),
            hard_timeout_ms: u64::from(spec.settle_ms).saturating_mul(4).max(1_000),
            fixed_wait_ms: 0,
            navigation_settled: true,
        };
        let collected = self.virtual_windows(index, action, &spec).await;
        self.driver.settle = original_settle;
        let restoration = match self.page_op(PageOp::RestoreVirtualRows).await {
            Ok(PageOpResult::VirtualRowsRestored(outcome)) => outcome,
            _ => VirtualRowsRestoration::Failed,
        };
        match collected {
            Ok(mut report) => {
                report.restoration = restoration;
                tracing::info!(stop = ?report.stop, ?restoration, "virtual rows collection stopped");
                if restoration != VirtualRowsRestoration::Restored {
                    return Err(fail(index, action, "restoration_failed_or_replaced"));
                }
                let charged: usize = report
                    .windows
                    .iter()
                    .map(|window| usize::try_from(window.transport_bytes).unwrap_or(usize::MAX))
                    .fold(0, usize::saturating_add);
                self.virtual_bytes_remaining = self.virtual_bytes_remaining.saturating_sub(charged);
                self.outputs.virtual_rows.push(report);
                Ok(())
            }
            Err(mut error) => {
                tracing::info!(stop = ?VirtualRowsStop::Failed, ?restoration, "virtual rows collection stopped");
                let detail = match restoration {
                    VirtualRowsRestoration::Restored => "; virtual rows restoration: restored",
                    VirtualRowsRestoration::Replaced => "; virtual rows restoration: replaced",
                    VirtualRowsRestoration::Failed => "; virtual rows restoration: failed",
                    VirtualRowsRestoration::Inactive => "; virtual rows restoration: inactive",
                    _ => "; virtual rows restoration: unavailable",
                };
                // Preserve egress, unavailable and action-denial classifications. Cleanup
                // context must never turn a refusal into a retryable browser failure.
                match &mut error {
                    RenderError::Navigation(message)
                    | RenderError::EgressDenied(message)
                    | RenderError::Browser(message)
                    | RenderError::Unavailable(message)
                    | RenderError::Action { reason: message, .. } => message.push_str(detail),
                    _ => {}
                }
                Err(error)
            }
        }
    }

    async fn virtual_windows(
        &self,
        index: usize,
        action: &ScrapeAction,
        spec: &VirtualRowsSpec,
    ) -> Result<VirtualRowsReport, RenderError> {
        let PageOpResult::VirtualRows(initial) = self.page_op(PageOp::BeginVirtualRows(spec.clone())).await?
        else {
            return Err(unexpected("begin_virtual_rows"));
        };
        let mut report = VirtualRowsReport::new(initial, spec.max_bytes);
        loop {
            let last = report.windows.last().ok_or_else(|| unexpected("virtual_rows"))?;
            if last.capped {
                report.stop = VirtualRowsStop::OutputCap;
                break;
            }
            if last.bottom {
                report.stop = VirtualRowsStop::Bottom;
                break;
            }
            if report.steps >= spec.max_steps {
                report.stop = VirtualRowsStop::StepCap;
                break;
            }
            let step = f64::from(last.scroll_step);
            self.scroll(
                index,
                action,
                ScrollDirection::Down,
                Some(&spec.container),
                Some(step),
            )
            .await?;
            report.steps = report.steps.saturating_add(1);
            // Capture first, then test the step cap: the final capped step is not omitted.
            let PageOpResult::VirtualRows(window) = self.page_op(PageOp::ReadVirtualRows).await? else {
                return Err(unexpected("read_virtual_rows"));
            };
            report.windows.push(window);
        }
        Ok(report)
    }

    /// Every element `selector` matches (at most `limit`) as locators of the current epoch.
    async fn resolve(&self, selector: &str, limit: u32) -> Result<Vec<RuntimeLocator>, RenderError> {
        let op = PageOp::ResolveAll {
            selector: selector.to_owned(),
            limit,
        };
        match self.page_op(op).await? {
            PageOpResult::Locators(found) => Ok(found),
            _ => Err(unexpected("resolve_all")),
        }
    }

    async fn observe(&self) -> Result<std::sync::Arc<ObservationBundle>, RenderError> {
        self.driver
            .handle
            .observe(spec::after_action())
            .await
            .map_err(render_error)
    }

    /// One page operation, a failure of the browser mapped like the rest of the render.
    async fn page_op(&self, op: PageOp) -> Result<PageOpResult, RenderError> {
        self.driver.handle.page_op(op).await.map_err(render_error)
    }

    /// What the journal records about a caller action: its index and kind, never text the
    /// caller typed or a selector's page content. `size` is a length, not a value.
    fn attribution(
        &self,
        index: usize,
        action: &ScrapeAction,
        addressed: &[u8],
        input_class: InputClass,
        size: Option<String>,
    ) -> Attribution {
        let kind = action.name();
        let summary = match size {
            Some(size) => format!("scrape action {index} ({kind}, {size})"),
            None => format!("scrape action {index} ({kind})"),
        };
        Attribution {
            strategy: EXPLICIT_ACTIONS_STRATEGY,
            strategy_version: STRATEGY_VERSION,
            hinted_risk: None,
            summary,
            element: Digest::of(TARGET_DOMAIN, addressed),
            input_class,
        }
    }

    /// Audit row of an action the safety kernel does not gate.
    async fn note(&self, index: usize, action: &ScrapeAction, extra: Option<serde_json::Value>) {
        let mut payload = serde_json::json!({
            "session_id": self.driver.session.id.0,
            "index": index,
            "type": action.name(),
        });
        if let (Some(obj), Some(serde_json::Value::Object(more))) = (payload.as_object_mut(), extra) {
            obj.extend(more);
        }
        if let Err(e) = self
            .driver
            .rc
            .stores
            .events
            .append(self.driver.rc.run, "scrape.action", payload)
            .await
        {
            tracing::warn!(error = %e, "scrape action event not recorded");
        }
    }

    /// After an action that may navigate: a main document the egress proxy refused is
    /// [`RenderError::EgressDenied`], a browser error page [`RenderError::Navigation`].
    async fn check_navigation(&self) -> Result<(), RenderError> {
        if let PageOpResult::Response { status, headers, .. } = self.page_op(PageOp::DocumentResponse).await?
        {
            if status == Some(403) && headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(DENIED_HEADER)) {
                return Err(RenderError::EgressDenied(
                    "the egress policy refused the page the action opened".to_owned(),
                ));
            }
        }
        if let PageOpResult::Html { url, .. } = self.page_op(PageOp::Html).await? {
            if url.starts_with("chrome-error:") {
                return Err(RenderError::Navigation(
                    "the page the action opened failed to load".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn fail(index: usize, action: &ScrapeAction, reason: &str) -> RenderError {
    RenderError::Action {
        index,
        kind: action.name(),
        reason: reason.to_owned(),
    }
}

/// A page operation answered with a result of another kind: a context bug, not the caller's.
fn unexpected(op: &str) -> RenderError {
    RenderError::Browser(format!("unexpected result of page operation {op}"))
}

fn drive_error(index: usize, action: &ScrapeAction, e: DriveFailure) -> RenderError {
    match e {
        DriveFailure::Denied | DriveFailure::Dropped(crate::DropReason::ConfirmDenied) => {
            fail(index, action, "denied")
        }
        DriveFailure::Dropped(reason) => fail(index, action, reason.as_str()),
        DriveFailure::Failed => fail(index, action, "failed"),
        DriveFailure::Session(e) => render_error(e),
    }
}

/// Facts of the page for keyboard input, which has no target element.
fn page_facts(bundle: &ObservationBundle) -> LiveTargetFacts {
    LiveTargetFacts {
        current_url: bundle.url.url.to_string(),
        ..LiveTargetFacts::default()
    }
}

fn shot_of(result: PageOpResult) -> Result<Shot, RenderError> {
    match result {
        PageOpResult::Bytes { bytes, content_type } => Ok(Shot { bytes, content_type }),
        _ => Err(unexpected("capture")),
    }
}

/// JSON type name of a script's return value (`javascriptReturns[].type` of the compatibility API).
fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// The key press that types `c`.
fn typed_chord(c: char) -> KeyChord {
    let key = match c {
        '\n' | '\r' => "Enter".to_owned(),
        '\t' => "Tab".to_owned(),
        other => other.to_string(),
    };
    KeyChord {
        key,
        modifiers: Modifiers::default(),
    }
}

/// `Enter`, `ArrowDown`, `a`, or a chord such as `Control+A` / `Shift+Tab`; `None` when the
/// key (or a modifier) is unknown.
fn parse_chord(spec: &str) -> Option<KeyChord> {
    let spec = spec.trim();
    // a lone `+` is the plus key, not an empty chord
    let (mods, key) = match spec.rsplit_once('+') {
        Some((mods, key)) if !key.is_empty() => (mods, key),
        _ => ("", spec),
    };
    let mut modifiers = Modifiers::default();
    for m in mods.split('+').filter(|m| !m.is_empty()) {
        match m.to_ascii_lowercase().as_str() {
            "control" | "ctrl" => modifiers.ctrl = true,
            "shift" => modifiers.shift = true,
            "alt" | "option" => modifiers.alt = true,
            "meta" | "command" | "cmd" => modifiers.meta = true,
            _ => return None,
        }
    }
    key_def(key)?;
    Some(KeyChord {
        key: key.to_owned(),
        modifiers,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn chords_parse_keys_and_modifiers_and_refuse_unknown_names() {
        let enter = parse_chord("Enter").unwrap();
        assert_eq!(enter.key, "Enter");
        assert_eq!(enter.modifiers, Modifiers::default());
        let select_all = parse_chord("Control+A").unwrap();
        assert_eq!(select_all.key, "A");
        assert!(select_all.modifiers.ctrl && !select_all.modifiers.shift);
        let back = parse_chord("shift+Tab").unwrap();
        assert!(back.modifiers.shift);
        let plus = parse_chord("+").unwrap();
        assert_eq!(plus.key, "+");
        assert!(parse_chord("Hyper+A").is_none());
        assert!(parse_chord("NoSuchKey").is_none());
        assert!(parse_chord("").is_none());
    }

    #[test]
    fn written_text_becomes_one_key_press_per_character() {
        let chords: Vec<KeyChord> = "a\tb\n".chars().map(typed_chord).collect();
        let keys: Vec<&str> = chords.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["a", "Tab", "b", "Enter"]);
    }

    #[test]
    fn json_values_get_the_compatibility_type_names() {
        use serde_json::json;
        let names: Vec<&str> = [
            json!(null),
            json!(true),
            json!(1.5),
            json!("s"),
            json!([1]),
            json!({"a": 1}),
        ]
        .iter()
        .map(json_type)
        .collect();
        assert_eq!(names, ["null", "boolean", "number", "string", "array", "object"]);
    }
}
