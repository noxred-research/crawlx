//! Lazy-content scroll and CSS candidate filtering: the CDP side of
//! [`BrowserContext::lazy_scroll`](crawlx_core::BrowserContext::lazy_scroll) and
//! [`BrowserContext::css_filter`](crawlx_core::BrowserContext::css_filter).
//!
//! Both run in the isolated world: they read and scroll the document but never
//! click, type or navigate, and need no `Runtime.enable`.

use super::{js, CdpContext};
use crawlx_core::browser::BrowserError;
use crawlx_core::dom_ops::{CssFilter, LazyScrollReport, LazyScrollSpec, MAX_LAZY_SCROLL_STEPS};
use crawlx_core::observation::{QuiescencePolicy, RuntimeLocator};
use serde_json::{json, Value};

/// Pixels of slack when comparing scroll offsets and document heights.
const PIXEL_TOLERANCE: u64 = 2;
/// Extra quiet windows a document that looks fully scrolled must survive before the scroll
/// stops, so lazy-load responses that land after the first window are still revealed
/// (katana `lazyScrollStableChecks`). They do not count as scroll steps.
const STABLE_CHECKS: u8 = 2;

/// Scroll position of the page: offset of the viewport top, document height and viewport
/// height, in whole CSS pixels.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Metrics {
    top: u64,
    height: u64,
    viewport: u64,
}

impl Metrics {
    fn from_json(v: &Value) -> Result<Self, BrowserError> {
        let get = |k: &str| {
            v.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| BrowserError::Script(format!("scroll metrics without `{k}`")))
        };
        Ok(Self {
            top: get("top")?,
            height: get("height")?,
            viewport: get("viewport")?,
        })
    }

    /// The viewport shows the end of the document.
    fn at_bottom(&self) -> bool {
        self.top + self.viewport + PIXEL_TOLERANCE >= self.height
    }

    /// Nothing left to scroll: at the bottom of a document that did not grow since `before`.
    fn finished_after(&self, before: &Self) -> bool {
        self.at_bottom() && self.height <= before.height + PIXEL_TOLERANCE
    }
}

/// The quiet window after one scroll step: no DOM mutation and no blocking request for
/// `settle_ms`, bounded so a page that never goes quiet cannot hold the scroll up.
fn quiet_window(settle_ms: u32) -> QuiescencePolicy {
    let window = u64::from(settle_ms);
    QuiescencePolicy {
        network_idle_window_ms: window,
        mutation_idle_window_ms: window,
        navigation_settled: true,
        hard_timeout_ms: window.saturating_mul(4).max(1_000),
        fixed_wait_ms: 0,
    }
}

impl CdpContext {
    async fn scroll_metrics(&self) -> Result<Metrics, BrowserError> {
        Metrics::from_json(&self.world_eval(None, js::SCROLL_METRICS, false).await?)
    }

    /// One viewport minus a 64 px overlap (so a sentinel between two steps is still crossed)
    /// of wheel scrolling at the viewport centre. Native input, not `window.scrollBy`: only
    /// input produces compositor frames in a headless tab, and without frames scroll handlers
    /// and `IntersectionObserver`s never run. It is the scroll of a user reading the page, not
    /// a journaled action: nothing is clicked, typed or submitted.
    async fn wheel_step(&self) -> Result<(), BrowserError> {
        let (_, sess) = self.session_for(None)?;
        let vp = sess.visual_viewport().await?;
        let dy = (vp.height - 64.0).max(1.0);
        crate::input::wheel_at(&sess, vp.width / 2.0, vp.height / 2.0, 0.0, dy).await
    }

    /// Scroll the active tab down one viewport at a time until `spec.max_steps` is spent or
    /// the document ends and stops growing, then return to the top.
    pub(crate) async fn lazy_scroll_impl(
        &mut self,
        spec: LazyScrollSpec,
    ) -> Result<LazyScrollReport, BrowserError> {
        let max = spec.max_steps.min(MAX_LAZY_SCROLL_STEPS);
        let mut report = LazyScrollReport::default();
        if max == 0 {
            return Ok(report);
        }
        let quiet = quiet_window(spec.settle_ms);
        // a tab that is not in front produces no frames, so scroll handlers and
        // IntersectionObservers would never run
        if let Ok((_, sess)) = self.session_for(None) {
            let _ = sess.send("Page.bringToFront", json!({})).await;
        }
        let mut metrics = self.scroll_metrics().await?;
        while report.steps < max {
            if metrics.height <= metrics.viewport + PIXEL_TOLERANCE {
                // nothing to scroll, so no scroll handler or observer can fire
                report.reached_bottom = true;
                break;
            }
            let before = metrics;
            self.wheel_step().await?;
            report.steps += 1;
            self.settle_impl(quiet).await?;
            metrics = self.scroll_metrics().await?;
            if !metrics.finished_after(&before) {
                continue;
            }
            let mut stable = true;
            for _ in 0..STABLE_CHECKS {
                self.settle_impl(quiet).await?;
                let now = self.scroll_metrics().await?;
                let still = now.finished_after(&metrics);
                metrics = now;
                if !still {
                    stable = false;
                    break;
                }
            }
            if stable {
                report.reached_bottom = true;
                break;
            }
        }
        report.document_height = metrics.height;
        self.world_eval(None, js::SCROLL_TOP, false).await?;
        Ok(report)
    }

    /// Evaluate `filter` for each of `targets` in the page (`Element.matches` for the include
    /// list, `Element.closest` for the exclude list). A target that is gone is not admitted.
    pub(crate) async fn css_filter_impl(
        &mut self,
        filter: &CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, BrowserError> {
        let mut out = Vec::with_capacity(targets.len());
        if filter.is_empty() {
            out.resize(targets.len(), true);
            return Ok(out);
        }
        for target in targets {
            let verdict = self
                .call_on_locator(
                    target,
                    js::CSS_ADMITS,
                    vec![
                        json!({ "value": filter.include }),
                        json!({ "value": filter.exclude }),
                    ],
                )
                .await?;
            out.push(verdict.and_then(|v| v.as_bool()).unwrap_or(false));
        }
        Ok(out)
    }
}

impl CdpContext {
    /// Pin identity before any rows are transferred. Never retry in a replacement world.
    pub(super) async fn begin_virtual_rows(
        &mut self,
        spec: crawlx_core::dom_ops::VirtualRowsSpec,
    ) -> Result<crawlx_core::dom_ops::VirtualRowsWindow, BrowserError> {
        spec.validate().map_err(BrowserError::Script)?;
        if self.virtual_rows.is_some() {
            return Err(BrowserError::Script(
                "virtual rows collection already active".into(),
            ));
        }
        let (tab, session, world) = self.world(None).await?;
        self.poll_counters(Some(&tab)).await?;
        let epoch = self.current_epoch_of(&tab).ok_or(BrowserError::TargetClosed)?;
        let encoded = serde_json::to_string(&spec)
            .map_err(|_| BrowserError::Script("invalid virtual rows spec".into()))?;
        let script = format!(
            r#"(() => {{
            const spec = {encoded};
            const matches = document.querySelectorAll(spec.container);
            if (matches.length !== 1) throw new Error('virtual rows requires exactly one container');
            const container = matches[0];
            container.querySelector(spec.rows);
            globalThis.__crawlxVirtualRows = {{container, document, spec,
                x: container.scrollLeft, y: container.scrollTop, rows: 0, bytes: 0}};
            return true;
        }})()"#
        );
        session.evaluate_in(world, &script, false).await?;
        self.virtual_rows = Some((tab, epoch, spec));
        self.read_virtual_rows().await
    }

    /// Capture after the caller's native, paced and journaled scroll has settled.
    pub(super) async fn read_virtual_rows(
        &mut self,
    ) -> Result<crawlx_core::dom_ops::VirtualRowsWindow, BrowserError> {
        let (tab, original, spec) = self
            .virtual_rows
            .as_ref()
            .ok_or_else(|| BrowserError::Script("virtual rows inactive".into()))?;
        let tab = tab.clone();
        let original = *original;
        let quiet = quiet_window(spec.settle_ms);
        if self.session_for(None)?.0 != tab {
            return Err(BrowserError::Script("virtual rows active tab changed".into()));
        }
        let settled = self.settle_impl(quiet).await?;
        if settled.settle_timeout {
            return Err(BrowserError::Script("virtual rows settle timeout".into()));
        }
        self.poll_counters(Some(&tab)).await?;
        let epoch = self.current_epoch_of(&tab).ok_or(BrowserError::TargetClosed)?;
        if epoch.document_seq != original.document_seq || epoch.navigation_seq != original.navigation_seq {
            return Err(BrowserError::Script("virtual rows document replaced".into()));
        }
        let (_, session, world) = self.world(Some(&tab)).await?;
        let mut value = session.evaluate_in(world, VIRTUAL_ROWS_READ, false).await?;
        value["epoch"] = serde_json::to_value(epoch)
            .map_err(|_| BrowserError::Script("invalid virtual rows epoch".into()))?;
        serde_json::from_value(value).map_err(|_| BrowserError::Script("invalid virtual rows window".into()))
    }

    /// Resolve only the pinned original element, never a replacement selector match.
    pub(super) async fn virtual_rows_target(&self) -> Result<Vec<RuntimeLocator>, BrowserError> {
        let (_, original, spec) = self
            .virtual_rows
            .as_ref()
            .ok_or_else(|| BrowserError::Script("virtual rows inactive".into()))?;
        let targets = self.resolve_all(&spec.container, 2).await?;
        if targets.len() != 1
            || targets[0].epoch.document_seq != original.document_seq
            || targets[0].epoch.navigation_seq != original.navigation_seq
        {
            return Err(BrowserError::Script("virtual rows container replaced".into()));
        }
        let same = self.call_on_locator(&targets[0],
            "function() { const s = globalThis.__crawlxVirtualRows; return !!s && s.document === document && s.container === this; }",
            Vec::new()).await?;
        if same != Some(Value::Bool(true)) {
            return Err(BrowserError::Script("virtual rows container replaced".into()));
        }
        Ok(targets)
    }

    /// Always called by context close, even if a cancelled render dropped its action future.
    pub(super) async fn restore_virtual_rows(
        &mut self,
    ) -> Result<crawlx_core::dom_ops::VirtualRowsRestoration, BrowserError> {
        use crawlx_core::dom_ops::VirtualRowsRestoration;
        let Some((tab, original, _)) = self.virtual_rows.take() else {
            return Ok(VirtualRowsRestoration::Inactive);
        };
        let result = async {
            self.poll_counters(Some(&tab)).await?;
            let epoch = self.current_epoch_of(&tab).ok_or(BrowserError::TargetClosed)?;
            let (_, session, world) = self.world(Some(&tab)).await?;
            if epoch.document_seq != original.document_seq || epoch.navigation_seq != original.navigation_seq
            {
                // A same-document navigation can reuse this element in a new SPA view.
                // Release only isolated-world bookkeeping; never scroll the stale pin.
                session
                    .evaluate_in(world, "delete globalThis.__crawlxVirtualRows", false)
                    .await?;
                return Ok(VirtualRowsRestoration::Replaced);
            }
            // This addresses only the saved element after its pinned epoch still matches.
            let value = session.evaluate_in(world, VIRTUAL_ROWS_RESTORE, true).await?;
            serde_json::from_value(value)
                .map_err(|_| BrowserError::Script("invalid virtual rows restoration".into()))
        }
        .await;
        // An inaccessible/replaced execution context is a visible cleanup failure.
        let outcome = result.unwrap_or(VirtualRowsRestoration::Failed);
        tracing::info!(?outcome, "virtual rows original-position restoration");
        Ok(outcome)
    }
}

/// All row-count and JSON UTF-8 byte limits apply inside Chromium, before by-value transfer.
const VIRTUAL_ROWS_READ: &str = r#"(() => {
    const s = globalThis.__crawlxVirtualRows;
    if (s && s.stopped) throw new Error('virtual rows allowance exhausted');
    if (!s || s.document !== document || !s.container.isConnected)
        throw new Error('virtual rows container replaced');
    const matches = document.querySelectorAll(s.spec.container);
    if (matches.length !== 1 || matches[0] !== s.container)
        throw new Error('virtual rows container replaced');
    const found = s.container.querySelectorAll(s.spec.rows);
    if (found.length === 0) throw new Error('virtual rows selector matched no rows');
    const rows = [];
    let bytes = 2, capped = found.length > s.spec.maxRowsPerWindow;
    const encoder = new TextEncoder();
    const count = Math.min(found.length, s.spec.maxRowsPerWindow);
    for (let i = 0; i < count; ++i) {
        const text = found[i].textContent;
        if (text.length > s.spec.maxBytes - s.bytes - bytes - 512) {
            capped = true; break;
        }
        const size = encoder.encode(JSON.stringify(text)).byteLength + (rows.length ? 1 : 0);
        if (s.rows >= s.spec.maxRows || s.bytes + bytes + size + 512 > s.spec.maxBytes) {
            capped = true; break;
        }
        rows.push(text); bytes += size; ++s.rows;
    }
    // Reserve a conservative bound for the fixed JSON window envelope before transfer.
    s.bytes += bytes + 512;
    capped = capped || s.bytes + 514 > s.spec.maxBytes || s.rows >= s.spec.maxRows;
    s.stopped = capped;
    return {rows, capped, transportBytes: bytes + 512, scrollStep: Math.max(1, s.container.clientHeight - 1),
        bottom: s.container.scrollTop + s.container.clientHeight >= s.container.scrollHeight - 1};
})()"#;

const VIRTUAL_ROWS_RESTORE: &str = r#"(async () => {
    const s = globalThis.__crawlxVirtualRows;
    delete globalThis.__crawlxVirtualRows;
    if (!s || s.document !== document || !s.container.isConnected) return 'replaced';
    try {
        s.container.scrollTo({left:s.x, top:s.y, behavior:'instant'});
        await new Promise(resolve => setTimeout(resolve, 50));
        if (!s.container.isConnected) return 'replaced';
        return Math.abs(s.container.scrollLeft-s.x) <= 1 && Math.abs(s.container.scrollTop-s.y) <= 1
            ? 'restored' : 'failed';
    } catch (_) { return 'failed'; }
})()"#;
