//! Revalidation and native-input action execution.
//!
//! `revalidate` checks the one chosen target: attached, identity unchanged, enabled,
//! visible (scrolling it into view with wheel events when needed), stable over two
//! animation frames, and hit-testable at up to five interior points through
//! `DOM.getNodeForLocation`. `perform` runs the action through `Input.dispatch*` at the
//! first passing hit point; the receipt's fidelity and lane come from the action variant.

use super::{js, state, synthetic, CdpContext};
use crate::cdp::{CdpSession, Quad, VisualViewport};
use crate::input;
use crawlx_core::action::{BrowserAction, OptionKey, PointerButton};
use crawlx_core::browser::BrowserError;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::ids::BackendNodeId;
use crawlx_core::observation::{ActionReceipt, BoundingBox, LiveTargetFacts, Revalidation, RuntimeLocator};
use crawlx_core::traffic::Fidelity;
use serde_json::{json, Value};
use std::future::Future;
use std::time::{Duration, Instant};

const ACT_GROUP: &str = "crawlx-act";
const MAX_SCROLL_STEPS: usize = 20;
const STABILITY_ROUNDS: usize = 3;
/// Most arrow-key presses one `SetRange` action sends.
const MAX_ARROW_PRESSES: u16 = 1000;

/// A target resolved into the isolated world of the session that owns it (the tab's, or an
/// out-of-process iframe's; `CdpContext::node_session`).
struct Resolved {
    tab: String,
    sess: CdpSession,
    /// Isolated-world execution context of `sess`.
    world: i64,
    object_id: String,
    /// Raw backend id for commands on `sess`.
    backend: i64,
    /// Public id (`state::join_node_id`) the tab's per-node bookkeeping is keyed by.
    node: i64,
    /// Node-id space of `sess` (0: the tab's own session).
    index: u32,
}

/// Internal outcome of the actionability checks.
enum Check {
    Actionable(Box<Actionable>),
    Detached,
    IdentityChanged,
    NotVisible,
    Disabled,
    Obscured(Option<i64>),
    Unstable,
    Stale(ObservationEpoch),
}

struct Actionable {
    facts: LiveTargetFacts,
    points: Vec<(f64, f64)>,
}

impl Check {
    fn into_revalidation(self) -> Revalidation {
        match self {
            Self::Actionable(a) => Revalidation::Actionable { live: a.facts },
            Self::Detached => Revalidation::Detached,
            Self::IdentityChanged => Revalidation::IdentityChanged,
            Self::NotVisible => Revalidation::NotVisible,
            Self::Disabled => Revalidation::Disabled,
            Self::Obscured(by) => Revalidation::Obscured {
                by_backend_node_id: by.map(BackendNodeId),
            },
            Self::Unstable => Revalidation::Unstable,
            Self::Stale(current) => Revalidation::StaleEpoch { current },
        }
    }

    fn into_error(self, current: ObservationEpoch) -> BrowserError {
        match self {
            Self::Actionable(_) => BrowserError::Script("unexpected actionable state".to_owned()),
            Self::Stale(e) => BrowserError::StaleLocator(e),
            Self::Detached => BrowserError::StaleLocator(current),
            Self::IdentityChanged => {
                BrowserError::Script("target not actionable: identity changed".to_owned())
            }
            Self::NotVisible => BrowserError::Script("target not actionable: not visible".to_owned()),
            Self::Disabled => BrowserError::Script("target not actionable: disabled".to_owned()),
            Self::Obscured(_) => BrowserError::Script("target not actionable: obscured".to_owned()),
            Self::Unstable => BrowserError::Script("target not actionable: unstable".to_owned()),
        }
    }
}

fn rect_close(a: &[f64], b: &[f64]) -> bool {
    a.len() == 4 && b.len() == 4 && a.iter().zip(b).all(|(x, y)| (x - y).abs() <= 1.0)
}

fn nums(v: Option<&Value>) -> Vec<f64> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_f64).collect())
        .unwrap_or_default()
}

/// Up to five hit-test points inside `quad` and the viewport: the centroid first, then four
/// points at 25%/75% of the bounding box, nearest the centroid first.
#[must_use]
pub fn sample_points(quad: &Quad, vp: &VisualViewport) -> Vec<(f64, f64)> {
    let b = quad.bounds();
    let (cx, cy) = quad.centroid();
    let mut pts = vec![(cx, cy)];
    for (fx, fy) in [(0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75)] {
        pts.push((b.x + b.w * fx, b.y + b.h * fy));
    }
    let mut kept: Vec<(f64, f64)> = pts
        .into_iter()
        .filter(|(x, y)| quad.contains(*x, *y) && *x >= 0.0 && *y >= 0.0 && *x < vp.width && *y < vp.height)
        .collect();
    let dist = |p: &(f64, f64)| (p.0 - cx).powi(2) + (p.1 - cy).powi(2);
    kept.sort_by(|a, b| dist(a).total_cmp(&dist(b)));
    kept
}

/// Largest wheel delta (CSS px) sent in one event.
const WHEEL_STEP_MAX: f64 = 800.0;
/// Wheel events in a row that moved nothing before wheel scrolling is given up on.
const MAX_STALLED_WHEELS: usize = 3;

/// Is `quad` placed well enough in `vp` to hit-test? Fully inside qualifies; so does a quad
/// whose centre is inside when it is larger than the viewport, or on the `last_attempt`.
fn quad_in_view(quad: &Quad, vp: &VisualViewport, last_attempt: bool) -> bool {
    let b = quad.bounds();
    let inside = b.x >= 0.0 && b.y >= 0.0 && b.x + b.w <= vp.width && b.y + b.h <= vp.height;
    let (cx, cy) = quad.centroid();
    let center_inside = cx >= 0.0 && cy >= 0.0 && cx < vp.width && cy < vp.height;
    inside || (center_inside && (last_attempt || b.w * b.h > vp.width * vp.height))
}

/// The innermost scrollable ancestor that clips the target (`js::CLIPPING_SCROLLER`).
#[derive(Clone, Copy, PartialEq, Debug)]
struct Scroller {
    /// Centre of the scroller's client box, main-frame viewport coordinates.
    x: f64,
    y: f64,
    /// Wheel delta that would bring the target to that centre.
    dx: f64,
    dy: f64,
}

impl Scroller {
    fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            x: v.get("x")?.as_f64()?,
            y: v.get("y")?.as_f64()?,
            dx: v.get("dx")?.as_f64()?,
            dy: v.get("dy")?.as_f64()?,
        })
    }
}

/// Where the target is relative to the viewport and to the scroller clipping it.
struct View {
    vp: VisualViewport,
    quad: Option<Quad>,
    scroller: Option<Scroller>,
}

/// The wheel event `(x, y, dx, dy)` that moves the target toward visibility: at the clipping
/// scroller's centre when that is on screen, otherwise at the viewport centre toward the target.
fn wheel_for(quad: &Quad, vp: &VisualViewport, scroller: Option<Scroller>) -> (f64, f64, f64, f64) {
    let on_screen = |x: f64, y: f64| x >= 0.0 && y >= 0.0 && x < vp.width && y < vp.height;
    match scroller {
        Some(s) if on_screen(s.x, s.y) => (
            s.x,
            s.y,
            s.dx.clamp(-WHEEL_STEP_MAX, WHEEL_STEP_MAX),
            s.dy.clamp(-WHEEL_STEP_MAX, WHEEL_STEP_MAX),
        ),
        _ => {
            let (cx, cy) = quad.centroid();
            (
                vp.width / 2.0,
                vp.height / 2.0,
                (cx - vp.width / 2.0).clamp(-WHEEL_STEP_MAX, WHEEL_STEP_MAX),
                (cy - vp.height / 2.0).clamp(-WHEEL_STEP_MAX, WHEEL_STEP_MAX),
            )
        }
    }
}

fn largest(quads: &[Quad]) -> Option<Quad> {
    quads.iter().copied().max_by(|a, b| a.area().total_cmp(&b.area()))
}

fn norm_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn option_key_json(k: &OptionKey) -> Value {
    match k {
        OptionKey::Value(v) => json!({ "value": v }),
        OptionKey::Label(l) => json!({ "label": l }),
        OptionKey::Index(i) => json!({ "index": i }),
    }
}

impl CdpContext {
    pub(super) fn current_epoch_of(&self, tab: &str) -> Option<ObservationEpoch> {
        self.state.lock().tabs.get(tab).map(|t| t.epoch)
    }

    /// Resolve `locator` into the isolated world, or say why that is impossible.
    async fn resolve(&self, locator: &RuntimeLocator) -> Result<Result<Resolved, Check>, BrowserError> {
        let tab = locator.tab.0.as_str();
        let Some(current) = self.current_epoch_of(tab) else {
            return Ok(Err(Check::Detached));
        };
        if locator.epoch.navigation_seq != current.navigation_seq
            || locator.epoch.document_seq != current.document_seq
        {
            return Ok(Err(Check::Stale(current)));
        }
        let node = locator.backend_node_id.0;
        let (sess, backend, index) = match self.node_session(tab, node) {
            Ok(s) => s,
            // the frame that owned the node detached: the node is gone with it
            Err(BrowserError::TargetClosed) if state::split_node_id(node).0 > 0 => {
                return Ok(Err(Check::Detached))
            }
            Err(e) => return Err(e),
        };
        let world = self.frame_world(tab, index).await?;
        match sess.resolve_node(backend, Some(world), ACT_GROUP).await {
            Ok(object_id) => Ok(Ok(Resolved {
                tab: tab.to_owned(),
                sess,
                world,
                object_id,
                backend,
                node,
                index,
            })),
            Err(BrowserError::Protocol { .. }) => Ok(Err(Check::Detached)),
            Err(e) => Err(e),
        }
    }

    async fn call_on(
        &self,
        r: &Resolved,
        function: &str,
        args: Vec<Value>,
        await_promise: bool,
    ) -> Result<Value, BrowserError> {
        r.sess
            .call_function_on(&r.object_id, function, args, await_promise)
            .await
    }

    /// Run `function` with `this` = the element `locator` names and return its by-value
    /// result; `None` when the element is gone (detached, or from an older document), which is
    /// not an error for read-only callers such as the CSS candidate filter.
    pub(super) async fn call_on_locator(
        &self,
        locator: &RuntimeLocator,
        function: &str,
        args: Vec<Value>,
    ) -> Result<Option<Value>, BrowserError> {
        match self.resolve(locator).await? {
            Ok(r) => {
                let out = self.call_on(&r, function, args, false).await.map(Some);
                r.sess.release_group(ACT_GROUP).await;
                out
            }
            Err(_) => Ok(None),
        }
    }

    /// Read the target's viewport, largest content quad and clipping scroller.
    async fn view(&self, r: &Resolved) -> Result<View, BrowserError> {
        let vp = r.sess.visual_viewport().await?;
        let quad = largest(&r.sess.content_quads(r.backend).await.unwrap_or_default());
        let scroller = if quad.is_some() {
            self.call_on(r, js::CLIPPING_SCROLLER, Vec::new(), false)
                .await
                .ok()
                .and_then(|v| Scroller::from_json(&v))
        } else {
            None
        };
        Ok(View { vp, quad, scroller })
    }

    /// Bring the target into the visual viewport and out of every scroller clipping it.
    /// Wheel events go to the clipping scroller's centre, or to the
    /// viewport centre when only the page needs to scroll; a few wheel attempts are made
    /// (`MAX_SCROLL_STEPS`, abandoned early when they move nothing). Only when the wheel cannot
    /// reveal the target is `DOM.scrollIntoViewIfNeeded` used, which the caller records as a
    /// forced scroll (`Fidelity::ScriptedScroll`, diagnostic lane). Returns the target's quad,
    /// the viewport and whether a forced scroll was needed; `None` when it cannot be revealed.
    async fn reveal(&self, r: &Resolved) -> Result<Option<(Quad, VisualViewport, bool)>, BrowserError> {
        let mut previous: Option<(f64, f64)> = None;
        let mut stalled = 0;
        for step in 0..=MAX_SCROLL_STEPS {
            let view = self.view(r).await?;
            let Some(quad) = view.quad else {
                return Ok(None);
            };
            if view.scroller.is_none() && quad_in_view(&quad, &view.vp, step == MAX_SCROLL_STEPS) {
                return Ok(Some((quad, view.vp, false)));
            }
            let b = quad.bounds();
            let here = (b.x, b.y);
            if previous.is_some_and(|(px, py)| (px - here.0).abs() < 0.5 && (py - here.1).abs() < 0.5) {
                stalled += 1;
            } else {
                stalled = 0;
            }
            previous = Some(here);
            if stalled >= MAX_STALLED_WHEELS || step == MAX_SCROLL_STEPS {
                break;
            }
            let (x, y, dx, dy) = wheel_for(&quad, &view.vp, view.scroller);
            input::wheel_at(&r.sess, x, y, dx, dy).await?;
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        // the wheel could not reveal the target: scroll it by script, as a diagnostic action
        match r
            .sess
            .send(
                "DOM.scrollIntoViewIfNeeded",
                json!({ "backendNodeId": r.backend }),
            )
            .await
        {
            Ok(_) => {}
            Err(BrowserError::Protocol { .. }) => return Ok(None),
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        let mut view = self.view(r).await?;
        // flush against a viewport edge is where fixed bars and the window margin hide a target
        let on_edge = view.quad.is_some_and(|q| {
            let b = q.bounds();
            b.x <= 1.0 || b.y <= 1.0 || b.x + b.w >= view.vp.width - 1.0 || b.y + b.h >= view.vp.height - 1.0
        });
        if on_edge {
            // a script error here only leaves the edge-aligned position the check below judges
            let _ = self.call_on(r, js::CENTER_IN_VIEW, Vec::new(), false).await;
            tokio::time::sleep(Duration::from_millis(60)).await;
            view = self.view(r).await?;
        }
        Ok(view
            .quad
            .filter(|q| view.scroller.is_none() && quad_in_view(q, &view.vp, true))
            .map(|q| (q, view.vp, true)))
    }

    /// The full actionability pipeline for one target.
    fn check_target<'a>(
        &'a self,
        locator: &'a RuntimeLocator,
        expected: Option<ObservationEpoch>,
    ) -> impl Future<Output = Result<Check, BrowserError>> + Send + 'a {
        Box::pin(self.check_target_inner(locator, expected))
    }

    async fn check_target_inner(
        &self,
        locator: &RuntimeLocator,
        expected: Option<ObservationEpoch>,
    ) -> Result<Check, BrowserError> {
        if let (Some(exp), Some(current)) = (expected, self.current_epoch_of(&locator.tab.0)) {
            if exp.navigation_seq != current.navigation_seq || exp.document_seq != current.document_seq {
                return Ok(Check::Stale(current));
            }
        }
        let r = match self.resolve(locator).await? {
            Ok(r) => r,
            Err(c) => return Ok(c),
        };
        let out = self.check_resolved(&r, locator).await;
        r.sess.release_group(ACT_GROUP).await;
        out
    }

    async fn check_resolved(&self, r: &Resolved, locator: &RuntimeLocator) -> Result<Check, BrowserError> {
        // 1. attached, and what the node is
        match r.sess.describe_node(r.backend).await {
            Ok(d) if d.node_type == 1 => {}
            Ok(_) | Err(BrowserError::Protocol { .. }) => return Ok(Check::Detached),
            Err(e) => return Err(e),
        }
        // a removed node can still be described; only a connected one is attached
        match self
            .call_on(r, "function () { return this.isConnected; }", Vec::new(), false)
            .await
        {
            Ok(v) if v.as_bool() == Some(true) => {}
            Ok(_) | Err(BrowserError::Script(_) | BrowserError::Protocol { .. }) => {
                return Ok(Check::Detached)
            }
            Err(e) => return Err(e),
        }
        // 2. identity: role/name against what the observation recorded
        let ax = r.sess.ax_node(r.backend).await.unwrap_or(None);
        let live_role = ax
            .as_ref()
            .and_then(|n| crate::cdp::ax_value_text(n.role.as_ref()));
        let live_name = ax
            .as_ref()
            .and_then(|n| crate::cdp::ax_value_text(n.name.as_ref()))
            .filter(|s| !s.is_empty());
        let recorded = self
            .state
            .lock()
            .tabs
            .get(&r.tab)
            .and_then(|t| t.identity.get(&r.node).cloned());
        let identity_mismatch = match (recorded, live_role.as_ref()) {
            (Some((role, name)), Some(live_role)) => {
                let same_name = name.as_deref().map(norm_ws) == live_name.as_deref().map(norm_ws);
                &role != live_role || !same_name
            }
            _ => false,
        };
        // 3. facts + stability over two animation frames (retried: animations settle)
        let mut facts = Value::Null;
        let mut stable = false;
        for round in 0..STABILITY_ROUNDS {
            facts = match self.call_on(r, js::ELEMENT_FACTS, Vec::new(), true).await {
                Ok(v) => v,
                Err(BrowserError::Script(_) | BrowserError::Protocol { .. }) => return Ok(Check::Detached),
                Err(e) => return Err(e),
            };
            if facts.get("connected").and_then(Value::as_bool) != Some(true) {
                return Ok(Check::Detached);
            }
            if facts.get("visible").and_then(Value::as_bool) != Some(true) {
                return Ok(Check::NotVisible);
            }
            // an unrendered node leaves the AX tree, so identity is judged only for visible ones
            if identity_mismatch {
                return Ok(Check::IdentityChanged);
            }
            if rect_close(&nums(facts.get("rect1")), &nums(facts.get("rect2"))) {
                stable = true;
                break;
            }
            if round + 1 < STABILITY_ROUNDS {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        if !stable {
            return Ok(Check::Unstable);
        }
        // 4. enabled
        let ax_disabled = ax.as_ref().is_some_and(|n| {
            n.properties
                .iter()
                .any(|p| p.name == "disabled" && p.value.value == Some(json!(true)))
        });
        let pointer_none = facts.get("pointerEvents").and_then(Value::as_str) == Some("none");
        if ax_disabled || facts.get("disabled").and_then(Value::as_bool) == Some(true) || pointer_none {
            return Ok(Check::Disabled);
        }
        // 5. geometry: bring into the viewport (wheel input first, a forced scroll as the fallback)
        let Some((quad, vp, forced_scroll)) = self.reveal(r).await? else {
            return Ok(Check::NotVisible);
        };
        // 6. hit-test sample points
        let candidates = sample_points(&quad, &vp);
        let mut passing: Vec<(f64, f64)> = Vec::new();
        let mut first_obstructor: Option<i64> = None;
        let world_ctx = r.world;
        for (x, y) in candidates {
            // `DOM.getNodeForLocation` takes document coordinates: add the page scroll offset
            let Some(hit) = r.sess.node_for_location(x + vp.x, y + vp.y).await? else {
                continue;
            };
            let ok = if hit == r.backend {
                true
            } else {
                match r.sess.resolve_node(hit, Some(world_ctx), ACT_GROUP).await {
                    Ok(iso_hit) => self
                        .call_on(r, js::IS_WITHIN, vec![json!({ "objectId": iso_hit })], false)
                        .await
                        .ok()
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    Err(_) => false,
                }
            };
            if ok {
                passing.push((x, y));
            } else if first_obstructor.is_none() {
                first_obstructor = Some(state::join_node_id(r.index, hit));
            }
        }
        if passing.is_empty() {
            return Ok(Check::Obscured(first_obstructor));
        }
        // 7. live facts
        let mut attributes: std::collections::BTreeMap<String, String> = facts
            .get("attrs")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        let (current_url, frame_url) = {
            let st = self.state.lock();
            let t = st.tabs.get(&r.tab);
            let url = t.map(|t| t.url.clone()).unwrap_or_default();
            let main = t.map(|t| t.main_frame.clone()).unwrap_or_default();
            let frame_url = if locator.frame.0 == main || locator.frame.0.is_empty() {
                None
            } else {
                Some(url.clone())
            };
            if let Some(t) = t {
                if t.confirm_nodes.contains(&r.node) {
                    attributes.insert("confirm-dialog".to_owned(), "true".to_owned());
                }
                if let Some(m) = t.observed_methods.get(&r.node) {
                    if !m.is_empty() {
                        attributes.insert(
                            "observed-methods".to_owned(),
                            m.iter().cloned().collect::<Vec<_>>().join(","),
                        );
                    }
                }
            }
            (url, frame_url)
        };
        if forced_scroll {
            if let Some(t) = self.state.lock().tabs.get_mut(&r.tab) {
                t.forced_scroll_nodes.insert(r.node);
            }
        }
        let bb = quad.bounds();
        // a node without an accessible name is classified by its text (`target_facts`), so
        // the live name mirrors that fallback and the kernel's identity digest holds
        let name = live_name.or_else(|| {
            facts
                .get("text")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
        });
        Ok(Check::Actionable(Box::new(Actionable {
            facts: LiveTargetFacts {
                role: live_role,
                name,
                tag: facts.get("tag").and_then(Value::as_str).map(str::to_owned),
                href: facts.get("href").and_then(Value::as_str).map(str::to_owned),
                bbox: BoundingBox {
                    x: bb.x,
                    y: bb.y,
                    width: bb.w,
                    height: bb.h,
                },
                hit_points: passing.clone(),
                frame_url,
                current_url,
                attributes,
                observed_form_hint: None,
            },
            points: passing,
        })))
    }

    pub(crate) async fn revalidate_impl(
        &mut self,
        locator: &RuntimeLocator,
        expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        let check = self.check_target(locator, Some(expected)).await?;
        // keep `current_epoch()` fresh for the caller's epoch policy
        let _ = self.poll_counters(Some(&locator.tab.0)).await;
        Ok(check.into_revalidation())
    }

    /// Resolve for actions that only need the node (focus, state), not a hit point.
    async fn resolve_for_action(&self, locator: &RuntimeLocator) -> Result<Resolved, BrowserError> {
        match self.resolve(locator).await? {
            Ok(r) => Ok(r),
            Err(c) => Err(c.into_error(self.current_epoch_of(&locator.tab.0).unwrap_or_default())),
        }
    }

    /// Session the pointer event goes to and the hit point, in that session's viewport: an
    /// out-of-process iframe receives its input on its own session.
    fn pointer_target<'a>(
        &'a self,
        locator: &'a RuntimeLocator,
    ) -> impl Future<Output = Result<(CdpSession, (f64, f64)), BrowserError>> + Send + 'a {
        Box::pin(self.pointer_target_inner(locator))
    }

    async fn pointer_target_inner(
        &self,
        locator: &RuntimeLocator,
    ) -> Result<(CdpSession, (f64, f64)), BrowserError> {
        match self.check_target(locator, None).await? {
            Check::Actionable(a) => {
                let (sess, _, _) = self.node_session(&locator.tab.0, locator.backend_node_id.0)?;
                let p = a
                    .points
                    .first()
                    .copied()
                    .ok_or_else(|| BrowserError::Script("no hit point".to_owned()))?;
                Ok((sess, p))
            }
            other => Err(other.into_error(self.current_epoch_of(&locator.tab.0).unwrap_or_default())),
        }
    }

    async fn focus(&self, r: &Resolved) -> Result<(), BrowserError> {
        r.sess
            .send("DOM.focus", json!({ "backendNodeId": r.backend }))
            .await
            .map(|_| ())
    }

    async fn ax_role(&self, r: &Resolved) -> String {
        r.sess
            .ax_node(r.backend)
            .await
            .ok()
            .flatten()
            .and_then(|n| crate::cdp::ax_value_text(n.role.as_ref()))
            .unwrap_or_default()
    }

    pub(crate) async fn perform_impl(
        &mut self,
        action: BrowserAction,
    ) -> Result<ActionReceipt, BrowserError> {
        if matches!(action, BrowserAction::SyntheticClick { .. }) && !self.ctl.config.synthetic_click_allowed
        {
            return Err(BrowserError::Unsupported(
                "SyntheticClick requires dynamic.syntheticClick".to_owned(),
            ));
        }
        let mut fidelity = action.fidelity();
        let started_at = self.ctl.shared.clock.now();
        let tab_id = match action.target() {
            Some(l) => l.tab.0.clone(),
            None => self.state.lock().active.clone(),
        };
        let navigates = matches!(action, BrowserAction::Navigate { .. });
        let dialogs_before = {
            let mut st = self.state.lock();
            let t = st.tabs.get_mut(&tab_id).ok_or(BrowserError::TargetClosed)?;
            if !navigates {
                t.open_network_epoch();
            }
            t.dialogs_total
        };
        let acted_on = action.target().map(|l| l.backend_node_id.0);
        // pointer actions whose targets a forced scroll brought into view are not trusted-UI
        let pointer_nodes: Vec<i64> = match &action {
            BrowserAction::Drag { source, destination } => {
                vec![source.backend_node_id.0, destination.backend_node_id.0]
            }
            _ => acted_on.into_iter().collect(),
        };
        self.run_action(&tab_id, action).await?;
        let finished_at = self.ctl.shared.clock.now();
        let network_epoch = {
            let mut st = self.state.lock();
            let t = st.tabs.get_mut(&tab_id);
            match t {
                Some(t) => {
                    t.perform_done_at = Instant::now();
                    t.last_action_node = acted_on;
                    let mut forced = false;
                    for n in &pointer_nodes {
                        // every node's mark is consumed, so no short-circuit
                        forced |= t.forced_scroll_nodes.remove(n);
                    }
                    if forced && fidelity == Fidelity::NativePointer {
                        fidelity = Fidelity::ScriptedScroll;
                    }
                    if t.dialogs_total > dialogs_before {
                        if let Some(n) = acted_on {
                            t.confirm_nodes.insert(n);
                        }
                    }
                    t.merge_observed_methods();
                    t.net_epoch
                }
                None => {
                    // the tab closed itself (e.g. CloseTab): report the epoch it had
                    crawlx_core::ids::NetworkEpochId::new()
                }
            }
        };
        self.bump();
        Ok(ActionReceipt {
            network_epoch,
            fidelity,
            lane: fidelity.lane(),
            started_at,
            finished_at,
        })
    }

    fn run_action<'a>(
        &'a mut self,
        tab_id: &'a str,
        action: BrowserAction,
    ) -> impl Future<Output = Result<(), BrowserError>> + Send + 'a {
        Box::pin(self.run_action_inner(tab_id, action))
    }

    #[allow(clippy::too_many_lines)]
    async fn run_action_inner(&mut self, tab_id: &str, action: BrowserAction) -> Result<(), BrowserError> {
        match action {
            BrowserAction::Click {
                target,
                button,
                modifiers,
            } => {
                self.bring_to_front(tab_id).await;
                let (sess, (x, y)) = self.pointer_target(&target).await?;
                input::click_at(&sess, x, y, button, &modifiers).await
            }
            BrowserAction::Hover { target } => {
                self.bring_to_front(tab_id).await;
                let (sess, (x, y)) = self.pointer_target(&target).await?;
                input::hover_at(&sess, x, y).await
            }
            BrowserAction::Drag { source, destination } => {
                self.bring_to_front(tab_id).await;
                let (sess, from) = self.pointer_target(&source).await?;
                let (_, to) = self.pointer_target(&destination).await?;
                self.drag(tab_id, &sess, from, to).await
            }
            BrowserAction::KeyboardActivate { target } => {
                let r = self.resolve_for_action(&target).await?;
                let out = async {
                    self.focus(&r).await?;
                    let role = self.ax_role(&r).await;
                    let key = if matches!(
                        role.as_str(),
                        "checkbox" | "radio" | "switch" | "menuitemcheckbox" | "menuitemradio"
                    ) {
                        "Space"
                    } else {
                        "Enter"
                    };
                    input::press_named(&r.sess, key).await
                }
                .await;
                r.sess.release_group(ACT_GROUP).await;
                out
            }
            BrowserAction::Type {
                target,
                value,
                clear_first,
            } => {
                let r = self.resolve_for_action(&target).await?;
                let out = async {
                    self.focus(&r).await?;
                    if clear_first {
                        let a = input::key_def("a")
                            .ok_or_else(|| BrowserError::Unsupported("key a".to_owned()))?;
                        input::press(&r.sess, &a, 2).await?;
                        input::press_named(&r.sess, "Backspace").await?;
                    }
                    // the only place a secret value is exposed
                    r.sess.insert_text(value.expose()).await
                }
                .await;
                r.sess.release_group(ACT_GROUP).await;
                out
            }
            BrowserAction::Select { target, options } => {
                let r = self.resolve_for_action(&target).await?;
                let out = self.select(tab_id, &r, &target, &options).await;
                r.sess.release_group(ACT_GROUP).await;
                out
            }
            BrowserAction::SetChecked { target, checked } => {
                let r = self.resolve_for_action(&target).await?;
                let out = async {
                    let cur = self.call_on(&r, js::CHECKED_STATE, Vec::new(), false).await?;
                    if cur.as_bool() == Some(checked) {
                        return Ok(());
                    }
                    self.focus(&r).await?;
                    input::press_named(&r.sess, "Space").await?;
                    let now = self.call_on(&r, js::CHECKED_STATE, Vec::new(), false).await?;
                    if now.as_bool() == Some(checked) {
                        Ok(())
                    } else {
                        Err(BrowserError::Script(format!(
                            "control did not become {}checked after Space",
                            if checked { "" } else { "un" }
                        )))
                    }
                }
                .await;
                r.sess.release_group(ACT_GROUP).await;
                out
            }
            BrowserAction::SetRange { target, value } => {
                let r = self.resolve_for_action(&target).await?;
                let out = self.set_range(&r, value).await;
                r.sess.release_group(ACT_GROUP).await;
                out
            }
            BrowserAction::Upload { target, fixture } => {
                let dir = self.ctl.shared.fixtures_dir.clone().ok_or_else(|| {
                    BrowserError::Unsupported("no fixtures_dir configured for uploads".to_owned())
                })?;
                let name = fixture.0.as_str();
                if name.is_empty() || name.contains(['/', '\\']) || name == ".." || name == "." {
                    return Err(BrowserError::Unsupported(format!("invalid fixture id {name:?}")));
                }
                let path = dir.join(name);
                let path = path
                    .canonicalize()
                    .map_err(|e| BrowserError::Io(format!("fixture {name}: {e}")))?;
                let r = self.resolve_for_action(&target).await?;
                let out = r
                    .sess
                    .send(
                        "DOM.setFileInputFiles",
                        json!({ "files": [path.display().to_string()], "backendNodeId": r.backend }),
                    )
                    .await
                    .map(|_| ());
                r.sess.release_group(ACT_GROUP).await;
                out
            }
            BrowserAction::Scroll { container, delta } => {
                self.bring_to_front(tab_id).await;
                let (_, sess) = self.session_for(Some(tab_id))?;
                let vp = sess.visual_viewport().await?;
                let (x, y) = match &container {
                    Some(c) => {
                        let r = self.resolve_for_action(c).await?;
                        let q = r.sess.content_quads(r.backend).await;
                        r.sess.release_group(ACT_GROUP).await;
                        q?.first()
                            .map(Quad::centroid)
                            .ok_or_else(|| BrowserError::Script("scroll container has no box".to_owned()))?
                    }
                    None => (vp.width / 2.0, vp.height / 2.0),
                };
                input::wheel_at(&sess, x, y, delta.dx, delta.dy).await
            }
            BrowserAction::Keys { sequence } => {
                let (_, sess) = self.session_for(Some(tab_id))?;
                for chord in &sequence {
                    input::press_chord(&sess, chord).await?;
                }
                Ok(())
            }
            BrowserAction::Navigate { url } => self.navigate_to(url.as_str()).await.map(|_| ()),
            BrowserAction::SolveCaptcha => self.solve_captcha().await,
            BrowserAction::SwitchTab { tab } => {
                let pending = {
                    let st = self.state.lock();
                    st.graph.pending(&tab.0).ok_or(BrowserError::TargetClosed)?
                };
                if pending {
                    if !self.state.lock().graph.admit(&tab.0) {
                        return Err(BrowserError::TabLimit(self.ctl.config.max_tabs));
                    }
                    super::setup_tab(&self.ctl, &self.state, &tab.0).await?;
                }
                self.ctl
                    .client
                    .call("Target.activateTarget", None, json!({ "targetId": tab.0 }))
                    .await?;
                self.state.lock().active = tab.0;
                Ok(())
            }
            BrowserAction::CloseTab { tab } => {
                {
                    let st = self.state.lock();
                    if !st.graph.contains(&tab.0) {
                        return Err(BrowserError::TargetClosed);
                    }
                    if st.graph.len() <= 1 {
                        return Err(BrowserError::Unsupported("cannot close the last tab".to_owned()));
                    }
                }
                if self.state.lock().graph.closed_download(&tab.0) {
                    // Chromium closes immediate download targets itself. Acknowledge that
                    // recorded terminal event through the same diagnostic action journal.
                    self.state.lock().remove_tab(&tab.0);
                    return Ok(());
                }
                self.ctl
                    .client
                    .call("Target.closeTarget", None, json!({ "targetId": tab.0 }))
                    .await?;
                self.state.lock().remove_tab(&tab.0);
                Ok(())
            }
            BrowserAction::SyntheticClick { target } => {
                let r = self.resolve_for_action(&target).await?;
                let out = self
                    .call_on(&r, synthetic::SYNTHETIC_CLICK, Vec::new(), false)
                    .await
                    .map(|_| ());
                r.sess.release_group(ACT_GROUP).await;
                out
            }
        }
    }

    async fn bring_to_front(&self, tab_id: &str) {
        let is_active = self.state.lock().active == tab_id;
        if !is_active {
            if let Ok((_, sess)) = self.session_for(Some(tab_id)) {
                let _ = sess.send("Page.bringToFront", json!({})).await;
            }
        }
    }

    async fn drag(
        &self,
        tab_id: &str,
        sess: &CdpSession,
        from: (f64, f64),
        to: (f64, f64),
    ) -> Result<(), BrowserError> {
        sess.send("Input.setInterceptDrags", json!({ "enabled": true }))
            .await?;
        if let Some(t) = self.state.lock().tabs.get_mut(tab_id) {
            t.drag_data = None;
        }
        let result = async {
            sess.dispatch_mouse("mouseMoved", from.0, from.1, "none", 0, 0, 0, None)
                .await?;
            sess.dispatch_mouse("mousePressed", from.0, from.1, "left", 1, 1, 0, None)
                .await?;
            let path = input::drag_path(from, to, 10);
            let mut intercepted: Option<Value> = None;
            for (i, (x, y)) in path.iter().enumerate() {
                sess.dispatch_mouse("mouseMoved", *x, *y, "left", 1, 0, 0, None)
                    .await?;
                if i == 1 {
                    // give the browser a moment to start a native HTML5 drag
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
                intercepted = self
                    .state
                    .lock()
                    .tabs
                    .get(tab_id)
                    .and_then(|t| t.drag_data.clone());
                if intercepted.is_some() {
                    break;
                }
            }
            if let Some(data) = intercepted {
                for kind in ["dragEnter", "dragOver", "drop"] {
                    sess.send(
                        "Input.dispatchDragEvent",
                        json!({ "type": kind, "x": to.0, "y": to.1, "data": data }),
                    )
                    .await?;
                }
            }
            sess.dispatch_mouse("mouseReleased", to.0, to.1, "left", 0, 1, 0, None)
                .await
        }
        .await;
        let _ = sess
            .send("Input.setInterceptDrags", json!({ "enabled": false }))
            .await;
        result
    }

    async fn select(
        &self,
        tab_id: &str,
        r: &Resolved,
        target: &RuntimeLocator,
        options: &[OptionKey],
    ) -> Result<(), BrowserError> {
        let state = self.call_on(r, js::SELECT_STATE, Vec::new(), false).await?;
        let is_select = state.get("isSelect").and_then(Value::as_bool) == Some(true);
        let multiple = state.get("multiple").and_then(Value::as_bool) == Some(true);
        if is_select {
            if multiple && options.len() > 1 {
                return Err(BrowserError::Unsupported(
                    "multi-option selection on a <select multiple> is not supported by native input"
                        .to_owned(),
                ));
            }
            for key in options {
                let idx = self
                    .call_on(
                        r,
                        js::SELECT_INDEX,
                        vec![json!({ "value": option_key_json(key) })],
                        false,
                    )
                    .await?
                    .as_i64()
                    .unwrap_or(-1);
                if idx < 0 {
                    return Err(BrowserError::Script(format!("no option matches {key:?}")));
                }
                self.focus(r).await?;
                input::press_named(&r.sess, "Home").await?;
                for _ in 0..idx {
                    input::press_named(&r.sess, "ArrowDown").await?;
                }
                let after = self.call_on(r, js::SELECT_STATE, Vec::new(), false).await?;
                if after.get("selected").and_then(Value::as_i64) != Some(idx) {
                    return Err(BrowserError::Script(format!(
                        "keyboard selection did not reach option {idx}"
                    )));
                }
            }
            return Ok(());
        }
        // custom listbox/combobox: open it with a real click, then click the matching option
        let (sess, (x, y)) = self.pointer_target(target).await?;
        input::click_at(
            &sess,
            x,
            y,
            PointerButton::Left,
            &crawlx_core::action::Modifiers::default(),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(80)).await;
        for key in options {
            let (_, _, ctx) = self.world(Some(tab_id)).await?;
            // find the option element in the isolated world, then click its box
            let expr = format!(
                "(function(){{ const f = {}; return f.call(null, {}); }})()",
                js::FIND_ROLE_OPTION,
                option_key_json(key)
            );
            let found = r
                .sess
                .send(
                    "Runtime.evaluate",
                    json!({ "expression": expr, "contextId": ctx, "returnByValue": false }),
                )
                .await?;
            let obj = found
                .get("result")
                .and_then(|o| o.get("objectId"))
                .and_then(Value::as_str)
                .ok_or_else(|| BrowserError::Script(format!("no visible option matches {key:?}")))?
                .to_owned();
            let desc = r
                .sess
                .send("DOM.describeNode", json!({ "objectId": obj }))
                .await?;
            let backend = desc
                .get("node")
                .and_then(|n| n.get("backendNodeId"))
                .and_then(Value::as_i64)
                .ok_or_else(|| BrowserError::Script("option has no backend node".to_owned()))?;
            let quads = r.sess.content_quads(backend).await?;
            let q = largest(&quads).ok_or_else(|| BrowserError::Script("option has no box".to_owned()))?;
            let (ox, oy) = q.centroid();
            input::click_at(
                &r.sess,
                ox,
                oy,
                PointerButton::Left,
                &crawlx_core::action::Modifiers::default(),
            )
            .await?;
        }
        Ok(())
    }

    async fn set_range(&self, r: &Resolved, target: f64) -> Result<(), BrowserError> {
        let st = self.call_on(r, js::RANGE_STATE, Vec::new(), false).await?;
        let get = |k: &str, d: f64| st.get(k).and_then(Value::as_f64).unwrap_or(d);
        let (cur, min, max, step) = (
            get("value", 0.0),
            get("min", 0.0),
            get("max", 100.0),
            get("step", 1.0).max(f64::EPSILON),
        );
        let target = target.clamp(min, max);
        self.focus(r).await?;
        if (target - cur).abs() < step / 2.0 {
            return Ok(());
        }
        if target <= min {
            input::press_named(&r.sess, "Home").await?;
        } else if target >= max {
            input::press_named(&r.sess, "End").await?;
        } else {
            let presses = ((target - cur) / step).round();
            let key = if presses > 0.0 { "ArrowRight" } else { "ArrowLeft" };
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "clamped to 0..=MAX_ARROW_PRESSES just above (NaN casts to 0)"
            )]
            let n = presses.abs().min(f64::from(MAX_ARROW_PRESSES)) as usize;
            for _ in 0..n {
                input::press_named(&r.sess, key).await?;
            }
        }
        let after = self.call_on(r, js::RANGE_STATE, Vec::new(), false).await?;
        let v = after.get("value").and_then(Value::as_f64).unwrap_or(cur);
        if (v - target).abs() > step / 2.0 + 1e-9 {
            return Err(BrowserError::Script(format!(
                "range ended at {v}, wanted {target} (step {step})"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn vp() -> VisualViewport {
        VisualViewport {
            x: 0.0,
            y: 0.0,
            width: 1280.0,
            height: 800.0,
        }
    }

    fn quad_at(x: f64, y: f64, w: f64, h: f64) -> Quad {
        Quad([(x, y), (x + w, y), (x + w, y + h), (x, y + h)])
    }

    #[test]
    fn quad_in_view_needs_the_whole_box_unless_oversized_or_last_attempt() {
        let v = vp();
        assert!(quad_in_view(&quad_at(10.0, 10.0, 50.0, 20.0), &v, false));
        // hanging off the bottom: only the last attempt accepts a centre-inside quad
        let partly = quad_at(10.0, 780.0, 50.0, 30.0);
        assert!(!quad_in_view(&partly, &v, false));
        assert!(quad_in_view(&partly, &v, true));
        // an element larger than the viewport can never fit: its centre decides
        assert!(quad_in_view(&quad_at(-100.0, -100.0, 2000.0, 1200.0), &v, false));
        // centre outside: never accepted
        assert!(!quad_in_view(&quad_at(10.0, 900.0, 50.0, 20.0), &v, true));
    }

    #[test]
    fn wheel_goes_to_an_on_screen_scroller_centre_else_to_the_viewport_centre() {
        let v = vp();
        let q = quad_at(100.0, 1500.0, 40.0, 20.0);
        let scroller = Scroller {
            x: 300.0,
            y: 200.0,
            dx: 0.0,
            dy: 5000.0,
        };
        // the scroller's own centre, delta clamped to one wheel step
        assert_eq!(
            wheel_for(&q, &v, Some(scroller)),
            (300.0, 200.0, 0.0, WHEEL_STEP_MAX)
        );
        // a scroller centred off screen cannot be wheeled: fall back to the page, toward the quad
        let hidden = Scroller {
            y: 2000.0,
            ..scroller
        };
        assert_eq!(
            wheel_for(&q, &v, Some(hidden)),
            (640.0, 400.0, -520.0, WHEEL_STEP_MAX)
        );
        assert_eq!(wheel_for(&q, &v, None), (640.0, 400.0, -520.0, WHEEL_STEP_MAX));
    }

    #[test]
    fn sample_points_start_at_centroid_and_stay_inside() {
        let q = Quad([(100.0, 100.0), (300.0, 100.0), (300.0, 200.0), (100.0, 200.0)]);
        let pts = sample_points(&q, &vp());
        assert_eq!(pts.len(), 5);
        assert_eq!(pts[0], (200.0, 150.0));
        for (x, y) in &pts {
            assert!(q.contains(*x, *y));
        }
        // ordered by distance from the centroid
        let d = |p: &(f64, f64)| (p.0 - 200.0).powi(2) + (p.1 - 150.0).powi(2);
        assert!(pts.windows(2).all(|w| d(&w[0]) <= d(&w[1])));
    }

    #[test]
    fn sample_points_drop_points_outside_viewport() {
        let q = Quad([(1200.0, 100.0), (1400.0, 100.0), (1400.0, 200.0), (1200.0, 200.0)]);
        let pts = sample_points(&q, &vp());
        assert!(pts.iter().all(|(x, _)| *x < 1280.0));
        assert!(pts.len() < 5);
    }

    #[test]
    fn rect_stability_threshold_is_one_pixel() {
        assert!(rect_close(&[0.0, 0.0, 10.0, 10.0], &[0.5, 0.0, 10.0, 10.9]));
        assert!(!rect_close(&[0.0, 0.0, 10.0, 10.0], &[2.0, 0.0, 10.0, 10.0]));
        assert!(!rect_close(&[0.0], &[0.0]));
    }

    #[test]
    fn option_keys_serialize_for_scripts() {
        assert_eq!(
            option_key_json(&OptionKey::Value("a".into())),
            json!({"value": "a"})
        );
        assert_eq!(
            option_key_json(&OptionKey::Label("A".into())),
            json!({"label": "A"})
        );
        assert_eq!(option_key_json(&OptionKey::Index(2)), json!({"index": 2}));
    }
}
