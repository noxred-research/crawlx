//! `CdpContext`: one browser context driven over CDP: an incognito context by
//! default, or the browser's default context under `ContextConfig::incognito = false`
//! (attached browsers).
//!
//! Layout: `state` is the event-driven bookkeeping (epochs, in-flight tracking, traffic),
//! `js` the isolated-world scripts, `nav` navigation and quiescence, `observe` the
//! observation capture, `actions` revalidation and native input, `storage` checkpointing.
//!
//! `current_epoch()` is synchronous, so it reports the epoch as of the last completed
//! operation or event: navigation/document bumps arrive through CDP events, and
//! `mutation_seq` is refreshed from the observer on every `observe`, `settle` poll,
//! `revalidate` and `perform`.

mod actions;
mod captcha;
mod capture;
mod dom_ops;
pub(crate) mod guard;
mod js;
mod nav;
mod observe;
mod page_ops;
mod selector;
pub mod state;
mod storage;
mod synthetic;
mod xhr;

use crate::backend::BackendShared;
use crate::cdp::{CdpClient, CdpEvent, CdpSession};
use crate::hooks::{self, DiscoverySink};
use crate::profile::ProfileBehavior;
use crate::target::TabGraph;
use async_trait::async_trait;
use crawlx_core::action::BrowserAction;
use crawlx_core::browser::{BrowserContext, BrowserError, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{
    ActionReceipt, DomSelector, NavigationResult, ObservationBundle, ObservationSpec, QuiescencePolicy,
    Revalidation, RuntimeLocator, SettleReport,
};
use crawlx_core::traffic::TrafficEvent;
use crawlx_core::url::CanonicalUrl;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use serde_json::{json, Value};
use state::{Counters, Followup, State, Tab};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

/// Bound on waiting for auto-attached child frames to finish their domain setup before an
/// observation (`CdpContext::wait_child_frames`).
const CHILD_FRAME_SETUP: Duration = Duration::from_secs(3);

/// Immutable per-context data shared with the pump task.
pub(crate) struct Ctl {
    pub client: CdpClient,
    pub shared: Arc<BackendShared>,
    pub config: ContextConfig,
    pub behavior: ProfileBehavior,
    pub browser_context_id: String,
    /// The context was created by us (incognito) and is disposed with the session; the
    /// default context of an attached browser is never disposed.
    pub owns_context: bool,
    pub notify: watch::Sender<u64>,
}

/// Add `delta` live sessions to `crawlx.browser.sessions` and
/// `crawlx.sessions.by_launch_profile{profile}`.
pub(crate) fn count_session(profile: LaunchProfile, delta: f64) {
    let metrics = Metrics::global();
    metrics.gauge(names::BROWSER_SESSIONS).add(delta, &[]);
    metrics
        .gauge(names::SESSIONS_BY_LAUNCH_PROFILE)
        .add(delta, &[("profile", profile.as_str())]);
}

/// Count one browser crash under a bounded `reason`
/// (`target_crashed` | `disconnected` | `action`).
pub(crate) fn count_crash(reason: &'static str) {
    Metrics::global()
        .counter(names::BROWSER_CRASHES)
        .inc_by(1, &[("reason", reason)]);
}

/// Observe a finished quiescence wait in `crawlx.settle.duration` and, when it hit the
/// hard timeout, `crawlx.settle.timeouts`.
pub(crate) fn record_settle(report: &SettleReport) {
    let metrics = Metrics::global();
    metrics
        .histogram(names::SETTLE_DURATION)
        .observe_duration(Duration::from_millis(report.waited_ms), &[]);
    if report.settle_timeout {
        metrics.counter(names::SETTLE_TIMEOUTS).inc();
    }
}

/// One browser context (incognito profile) with its tab graph.
pub struct CdpContext {
    pub(crate) ctl: Arc<Ctl>,
    pub(crate) state: Arc<Mutex<State>>,
    pub(crate) notified: watch::Receiver<u64>,
    pump: JoinHandle<()>,
    pub(crate) seq: u64,
    closed: bool,
    /// Counted in `crawlx.browser.sessions`; set once creation succeeded so a context that
    /// failed half-way and was disposed never decrements what it never added.
    counted: bool,
    /// Report of the most recent `settle`, attached to the next observation.
    pub(crate) last_settle: Option<SettleReport>,
    /// A pre-existing tab of the default context adopted as home (`incognito = false`);
    /// it belongs to the browser's owner and is left open on dispose.
    adopted_tab: Option<String>,
    /// Pinned virtual-row collection identity; cleanup survives cancellation of its waiter.
    pub(super) virtual_rows: Option<(String, ObservationEpoch, crawlx_core::dom_ops::VirtualRowsSpec)>,
}

impl CdpContext {
    /// Create a browser context with one blank tab: a fresh incognito context, or under
    /// `config.incognito = false` the browser's default context (adopting its first open
    /// page, else opening one).
    pub(crate) async fn create(
        shared: Arc<BackendShared>,
        config: ContextConfig,
    ) -> Result<Self, BrowserError> {
        let client = shared.client.clone();
        let behavior = ProfileBehavior::of(config.launch_profile, config.console_capture);
        if config.response_bodies != crawlx_core::config::ResponseBodies::MetadataOnly
            && config.response_body_sink.is_none()
        {
            return Err(BrowserError::Unsupported(
                "response body capture requires a retention-policy body sink".to_owned(),
            ));
        }
        if config.response_bodies == crawlx_core::config::ResponseBodies::Full && config.captcha.is_some() {
            return Err(BrowserError::Unsupported(
                "full response capture cannot safely retain CAPTCHA callback responses".to_owned(),
            ));
        }
        if config.page_hooks && behavior.is_stealth() {
            return Err(BrowserError::Unsupported(
                "page hooks run in the page's main world and are refused under the stealth profile"
                    .to_owned(),
            ));
        }
        if config.page_hook_options.any() && behavior.is_stealth() {
            return Err(BrowserError::Unsupported(
                "page hook options run in the page's main world and are refused under the stealth profile"
                    .to_owned(),
            ));
        }
        if config.stealth_patches && !behavior.is_stealth() {
            return Err(BrowserError::Unsupported(
                "stealth patches need the stealth launch profile".to_owned(),
            ));
        }
        if config.browser_profile.is_some() && config.incognito {
            return Err(BrowserError::Unsupported(
                "a persistent browser profile needs incognito = false: only the default browser context \
                 is written to the profile directory"
                    .to_owned(),
            ));
        }

        let (browser_context_id, adopt) = if config.incognito {
            let mut params = json!({ "disposeOnDetach": false });
            let proxy_port = config.egress_proxy_port;
            if let Some(port) = proxy_port.filter(|p| Some(*p) != shared.egress_proxy_port) {
                params["proxyServer"] = json!(format!("http://127.0.0.1:{port}"));
                params["proxyBypassList"] = json!("<-loopback>");
            }
            let created = client.call("Target.createBrowserContext", None, params).await?;
            let id = created
                .get("browserContextId")
                .and_then(Value::as_str)
                .ok_or_else(|| BrowserError::Protocol {
                    method: "Target.createBrowserContext".to_owned(),
                    message: "no browserContextId".to_owned(),
                })?
                .to_owned();
            (id, None)
        } else {
            default_context(&client, config.browser_profile.is_none()).await?
        };

        let (notify, notified) = watch::channel(0u64);
        let ctl = Arc::new(Ctl {
            client: client.clone(),
            shared,
            owns_context: config.incognito,
            config,
            behavior,
            browser_context_id: browser_context_id.clone(),
            notify,
        });
        let state = Arc::new(Mutex::new(
            State::new(
                &browser_context_id,
                TabGraph::new(ctl.config.max_tabs),
                behavior.console_capture,
            )
            .with_controls(ctl.config.request_controls.clone()),
        ));
        state.lock().capture_full = ctl.config.response_bodies == crawlx_core::config::ResponseBodies::Full;
        state.lock().capture_text =
            ctl.config.response_bodies == crawlx_core::config::ResponseBodies::TextCapped;
        let mut download = json!({ "behavior": "deny", "eventsEnabled": true });
        if ctl.config.incognito {
            download["browserContextId"] = json!(browser_context_id);
        }
        client.call("Browser.setDownloadBehavior", None, download).await?;
        // Subscribe before creating the first target so no event is missed.
        let rx = client.subscribe();
        let pump = tokio::spawn(crawlx_core::custody::inherit(pump(
            Arc::clone(&ctl),
            Arc::clone(&state),
            rx,
        )));
        let mut this = Self {
            ctl,
            state,
            notified,
            pump,
            seq: 0,
            closed: false,
            counted: false,
            last_settle: None,
            adopted_tab: None,
            virtual_rows: None,
        };
        // cookies first: no request of the first tab may go out without them
        let opened = match this.seed_request_cookies().await {
            Ok(()) => match adopt {
                Some(home) => this.adopt_home_tab(home).await,
                None => this.open_home_tab().await,
            },
            Err(e) => Err(e),
        };
        if let Err(e) = opened {
            let _ = this.dispose().await;
            return Err(e);
        }
        this.counted = true;
        count_session(this.ctl.shared.launch_profile, 1.0);
        Ok(this)
    }

    /// Seed `fetch.cookies` into the cookie jar of this browser context (`Storage.setCookies`)
    /// before any tab loads. The jar is shared by every tab, popup and out-of-process frame of
    /// the context, so one call covers them all (re-sending from each frame session would
    /// overwrite values a server renewed). Chromium applies `SameSite`/domain rules itself:
    /// a cookie reaches only the hosts matching its `domain` and `path`.
    ///
    /// # Errors
    /// The protocol error when Chromium rejects a cookie.
    async fn seed_request_cookies(&self) -> Result<(), BrowserError> {
        let cookies: Vec<Value> = self
            .ctl
            .config
            .request_controls
            .cookies()
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "value": c.value.expose(),
                    "domain": cookie_domain(&c.domain),
                    "path": c.path,
                })
            })
            .collect();
        if cookies.is_empty() {
            return Ok(());
        }
        self.ctl
            .client
            .call(
                "Storage.setCookies",
                None,
                json!({ "cookies": cookies, "browserContextId": self.ctl.browser_context_id }),
            )
            .await
            .map(|_| ())
    }

    /// Take over a page of the default context as the home tab; a pre-existing page stays
    /// open on dispose (it belongs to the browser's owner), one we created is closed.
    async fn adopt_home_tab(&mut self, home: DefaultHome) -> Result<(), BrowserError> {
        {
            let mut st = self.state.lock();
            st.graph.add_home(&home.target_id, &home.url);
            st.active.clone_from(&home.target_id);
        }
        if !home.created {
            self.adopted_tab = Some(home.target_id.clone());
        }
        setup_tab(&self.ctl, &self.state, &home.target_id).await
    }

    async fn open_home_tab(&mut self) -> Result<(), BrowserError> {
        let created = self
            .ctl
            .client
            .call(
                "Target.createTarget",
                None,
                json!({ "url": "about:blank", "browserContextId": self.ctl.browser_context_id }),
            )
            .await?;
        let target_id = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| BrowserError::Protocol {
                method: "Target.createTarget".to_owned(),
                message: "no targetId".to_owned(),
            })?
            .to_owned();
        {
            let mut st = self.state.lock();
            st.graph.add_home(&target_id, "about:blank");
            st.active.clone_from(&target_id);
        }
        setup_tab(&self.ctl, &self.state, &target_id).await
    }

    /// Wake waiters (called by the pump and by operations that change state).
    pub(crate) fn bump(&self) {
        self.ctl.notify.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Session of tab `tab` (or the active tab); errors if the tab is gone or crashed.
    pub(crate) fn session_for(&self, tab: Option<&str>) -> Result<(String, CdpSession), BrowserError> {
        let st = self.state.lock();
        let id = tab.map_or(st.active.as_str(), |t| t);
        let t = st.tabs.get(id).ok_or(BrowserError::TargetClosed)?;
        if t.crashed {
            return Err(BrowserError::TargetCrashed);
        }
        Ok((
            t.target_id.clone(),
            CdpSession {
                client: self.ctl.client.clone(),
                session_id: t.session.clone(),
            },
        ))
    }

    /// Wait until `cond` holds for the state, a notification arrives, or `timeout` elapses.
    pub(crate) async fn wait_until(
        &self,
        timeout: Duration,
        mut cond: impl FnMut(&State) -> bool,
    ) -> Result<(), BrowserError> {
        let mut rx = self.notified.clone();
        let deadline = Instant::now() + timeout;
        loop {
            {
                let st = self.state.lock();
                if cond(&st) {
                    return Ok(());
                }
                if st.closed || self.ctl.client.is_closed() {
                    return Err(BrowserError::TargetClosed);
                }
                if st.active_tab().is_some_and(|t| t.crashed) {
                    return Err(BrowserError::TargetCrashed);
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(BrowserError::Timeout(
                    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                ));
            }
            if tokio::time::timeout(remaining, rx.changed()).await.is_err() {
                return Err(BrowserError::Timeout(
                    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                ));
            }
        }
    }

    /// Isolated-world execution context of `tab`'s main frame, created on first use.
    pub(crate) async fn world(&self, tab: Option<&str>) -> Result<(String, CdpSession, i64), BrowserError> {
        let (target_id, sess) = self.session_for(tab)?;
        let (cached, frame) = {
            let st = self.state.lock();
            let t = st.tabs.get(&target_id).ok_or(BrowserError::TargetClosed)?;
            (t.world_ctx, t.main_frame.clone())
        };
        if let Some(c) = cached {
            return Ok((target_id, sess, c));
        }
        let r = sess
            .send(
                "Page.createIsolatedWorld",
                json!({ "frameId": frame, "worldName": js::WORLD_NAME, "grantUniveralAccess": false }),
            )
            .await?;
        let ctx = r
            .get("executionContextId")
            .and_then(Value::as_i64)
            .ok_or_else(|| BrowserError::Protocol {
                method: "Page.createIsolatedWorld".to_owned(),
                message: "no executionContextId".to_owned(),
            })?;
        sess.evaluate_in(ctx, js::OBSERVER, false).await?;
        if let Some(t) = self.state.lock().tabs.get_mut(&target_id) {
            t.world_ctx = Some(ctx);
        }
        Ok((target_id, sess, ctx))
    }

    fn invalidate_world(&self, target_id: &str) {
        if let Some(t) = self.state.lock().tabs.get_mut(target_id) {
            t.world_ctx = None;
        }
    }

    /// Session and raw backend id of public node id `node` in `tab`: the tab's own session
    /// for index 0, else the auto-attached child frame of that index (`state::split_node_id`).
    pub(crate) fn node_session(&self, tab: &str, node: i64) -> Result<(CdpSession, i64, u32), BrowserError> {
        let (index, raw) = state::split_node_id(node);
        if index == 0 {
            let (_, sess) = self.session_for(Some(tab))?;
            return Ok((sess, raw, 0));
        }
        let st = self.state.lock();
        let t = st.tabs.get(tab).ok_or(BrowserError::TargetClosed)?;
        if t.crashed {
            return Err(BrowserError::TargetCrashed);
        }
        let child = t.child_by_index(index).ok_or(BrowserError::TargetClosed)?;
        Ok((
            CdpSession {
                client: self.ctl.client.clone(),
                session_id: child.session.clone(),
            },
            raw,
            index,
        ))
    }

    /// Isolated-world execution context of child frame `index` of `tab` (its root frame),
    /// created on first use; index 0 is the tab's main-frame world.
    pub(crate) async fn frame_world(&self, tab: &str, index: u32) -> Result<i64, BrowserError> {
        if index == 0 {
            return self.world(Some(tab)).await.map(|(_, _, ctx)| ctx);
        }
        let (frame, cached, session) = {
            let st = self.state.lock();
            let t = st.tabs.get(tab).ok_or(BrowserError::TargetClosed)?;
            let (frame, child) = t
                .frames
                .iter()
                .find(|(_, f)| f.index == index)
                .ok_or(BrowserError::TargetClosed)?;
            (frame.clone(), child.world_ctx, child.session.clone())
        };
        if let Some(c) = cached {
            return Ok(c);
        }
        let sess = CdpSession {
            client: self.ctl.client.clone(),
            session_id: session,
        };
        let r = sess
            .send(
                "Page.createIsolatedWorld",
                json!({ "frameId": frame, "worldName": js::WORLD_NAME, "grantUniveralAccess": false }),
            )
            .await?;
        let ctx = r
            .get("executionContextId")
            .and_then(Value::as_i64)
            .ok_or_else(|| BrowserError::Protocol {
                method: "Page.createIsolatedWorld".to_owned(),
                message: "no executionContextId".to_owned(),
            })?;
        if let Some(f) = self
            .state
            .lock()
            .tabs
            .get_mut(tab)
            .and_then(|t| t.frames.get_mut(&frame))
        {
            f.world_ctx = Some(ctx);
        }
        Ok(ctx)
    }

    /// Wait (bounded) until every auto-attached child frame of `tab` finished its setup, so
    /// an observation right after a navigation sees the out-of-process iframes too.
    pub(crate) async fn wait_child_frames(&self, tab: &str) {
        let tab = tab.to_owned();
        let _ = self
            .wait_until(CHILD_FRAME_SETUP, |st| {
                st.tabs
                    .get(&tab)
                    .is_none_or(|t| t.frames.values().all(|f| f.ready))
            })
            .await;
    }

    /// `Runtime.evaluate` in the isolated world, retrying once if the context was replaced.
    pub(crate) async fn world_eval(
        &self,
        tab: Option<&str>,
        expr: &str,
        await_promise: bool,
    ) -> Result<Value, BrowserError> {
        for attempt in 0..2 {
            let (target_id, sess, ctx) = self.world(tab).await?;
            match sess.evaluate_in(ctx, expr, await_promise).await {
                Err(BrowserError::Protocol { message, .. })
                    if attempt == 0 && message.to_ascii_lowercase().contains("context") =>
                {
                    self.invalidate_world(&target_id);
                }
                other => return other,
            }
        }
        Err(BrowserError::Script("isolated world unavailable".to_owned()))
    }

    /// Read the observer's counters and fold them into the tab's epoch.
    pub(crate) async fn poll_counters(&self, tab: Option<&str>) -> Result<Counters, BrowserError> {
        let v = self.world_eval(tab, js::READ_COUNTERS, false).await?;
        let get = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or_default();
        let c = Counters {
            records: get("records"),
            added: get("added"),
            removed: get("removed"),
            attrs: get("attrs"),
            text: get("text"),
            stable: get("stable"),
            volatile: get("volatile"),
            volatile_recent: u32::try_from(get("volatile_recent")).unwrap_or(u32::MAX),
            stable_age_ms: v.get("stable_age_ms").and_then(Value::as_u64),
        };
        let (target_id, _) = self.session_for(tab)?;
        if v.is_null() {
            // observer missing (document replaced between calls): treat as a fresh document
            self.invalidate_world(&target_id);
            return Ok(Counters::default());
        }
        let mut st = self.state.lock();
        if let Some(t) = st.tabs.get_mut(&target_id) {
            t.apply_counters(c, Instant::now());
        }
        Ok(c)
    }

    /// Evaluate `expression` in the isolated world (never the page's main world) and return
    /// its by-value result. Works under every profile; it does not need `Runtime.enable`.
    ///
    /// # Errors
    /// [`BrowserError::Script`] when the expression throws or the isolated world cannot be
    /// (re)created, [`BrowserError::Protocol`] / [`BrowserError::TargetClosed`] when the tab's
    /// CDP session fails.
    pub async fn evaluate_isolated(&self, expression: &str) -> Result<Value, BrowserError> {
        self.world_eval(None, expression, false).await
    }

    /// Console messages captured so far (`Standard` profile with console capture only).
    #[must_use]
    pub fn console_messages(&self) -> Vec<String> {
        self.state
            .lock()
            .active_tab()
            .map(|t| {
                t.console
                    .iter()
                    .map(|line| {
                        self.ctl
                            .config
                            .captcha_secrets
                            .redact(line)
                            .unwrap_or_else(|_| "[REDACTED]".to_owned())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Ids of the tabs currently open.
    #[must_use]
    pub fn tab_ids(&self) -> Vec<String> {
        self.state.lock().graph.ids()
    }

    /// Popups rejected by the tab policy so far.
    #[must_use]
    pub fn rejected_popups(&self) -> u64 {
        self.state.lock().graph.rejected()
    }

    /// CDP methods sent on the shared connection so far.
    #[must_use]
    pub fn cdp_transcript(&self) -> Vec<String> {
        self.ctl.client.transcript()
    }

    /// Read and clear the page-hooks discovery sink of the active tab
    /// (`ContextConfig::page_hooks`), mapping listener CSS paths to backend
    /// node ids. Empty when the hooks are off or the document has none installed.
    /// `observe` drains the sink itself into the bundle, so call this between
    /// observations only.
    ///
    /// # Errors
    /// [`BrowserError::Script`] when the drain result has an unexpected shape, otherwise the
    /// CDP call errors ([`BrowserError::TargetClosed`], [`BrowserError::Protocol`]).
    pub async fn drain_discovery(&self) -> Result<DiscoverySink, BrowserError> {
        if !self.ctl.config.page_hooks {
            return Ok(DiscoverySink::default());
        }
        let (_, sess) = self.session_for(None)?;
        let v = sess
            .send(
                "Runtime.evaluate",
                json!({ "expression": hooks::DRAIN_EXPRESSION, "returnByValue": true }),
            )
            .await?;
        let v = crate::cdp::runtime_result("Runtime.evaluate", &v)?;
        let mut sink = DiscoverySink::from_value(&v).map_err(BrowserError::Script)?;
        let paths: Vec<String> = sink
            .candidate_paths(&crate::snapshot::LISTENER_EVENTS)
            .into_iter()
            .map(str::to_owned)
            .collect();
        if paths.is_empty() {
            return Ok(sink);
        }
        let root = sess.send("DOM.getDocument", json!({ "depth": 0 })).await?;
        let Some(root_id) = root
            .get("root")
            .and_then(|r| r.get("nodeId"))
            .and_then(Value::as_i64)
        else {
            return Ok(sink);
        };
        for path in paths {
            let found = sess
                .send(
                    "DOM.querySelector",
                    json!({ "nodeId": root_id, "selector": path }),
                )
                .await
                .ok()
                .and_then(|v| v.get("nodeId").and_then(Value::as_i64))
                .filter(|id| *id != 0);
            let Some(node_id) = found else { continue };
            let backend = sess
                .send("DOM.describeNode", json!({ "nodeId": node_id }))
                .await
                .ok()
                .and_then(|v| {
                    v.get("node")
                        .and_then(|n| n.get("backendNodeId"))
                        .and_then(Value::as_i64)
                });
            if let Some(b) = backend {
                for l in sink.listeners.iter_mut().filter(|l| l.css_path == path) {
                    l.backend_node_id = Some(b);
                }
            }
        }
        Ok(sink)
    }

    /// Release the session's slot in the session gauges exactly once.
    fn uncount_session(&mut self) {
        if self.counted {
            self.counted = false;
            count_session(self.ctl.shared.launch_profile, -1.0);
        }
    }

    async fn dispose(&mut self) -> Result<(), BrowserError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.uncount_session();
        let ids = {
            let mut st = self.state.lock();
            st.closed = true;
            st.tabs.keys().cloned().collect::<Vec<_>>()
        };
        for id in ids {
            // an adopted tab belongs to the browser's owner: detach, never close
            if self.adopted_tab.as_deref() == Some(id.as_str()) {
                continue;
            }
            let _ = self
                .ctl
                .client
                .call("Target.closeTarget", None, json!({ "targetId": id }))
                .await;
        }
        if !self.ctl.owns_context {
            self.pump.abort();
            return Ok(());
        }
        let r = self
            .ctl
            .client
            .call(
                "Target.disposeBrowserContext",
                None,
                json!({ "browserContextId": self.ctl.browser_context_id }),
            )
            .await
            .map(|_| ());
        self.pump.abort();
        match r {
            Err(BrowserError::TargetClosed) => Ok(()),
            other => other,
        }
    }
}

/// A page of the browser's default context used as the home tab (`incognito = false`).
struct DefaultHome {
    target_id: String,
    url: String,
    /// We opened it (closed on dispose) rather than adopted it.
    created: bool,
}

/// The default browser context: its id and its first open page (`adopt_existing`), or a page
/// created in it. `Target.getBrowserContexts` lists only contexts created over CDP, so a page
/// whose context is not listed lives in the default context. A persistent browser profile never
/// adopts: concurrent sessions of one browser would otherwise share a tab.
async fn default_context(
    client: &CdpClient,
    adopt_existing: bool,
) -> Result<(String, Option<DefaultHome>), BrowserError> {
    let created = client.call("Target.getBrowserContexts", None, json!({})).await?;
    let created_ids: Vec<String> = created
        .get("browserContextIds")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    let targets = client.call("Target.getTargets", None, json!({})).await?;
    let existing = targets
        .get("targetInfos")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|t| {
            adopt_existing
                && t.get("type").and_then(Value::as_str) == Some("page")
                && t.get("browserContextId")
                    .and_then(Value::as_str)
                    .is_some_and(|id| !created_ids.iter().any(|c| c == id))
        });
    if let Some(t) = existing {
        let ctx = t
            .get("browserContextId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let target_id = t.get("targetId").and_then(Value::as_str).unwrap_or_default();
        let url = t.get("url").and_then(Value::as_str).unwrap_or("about:blank");
        return Ok((
            ctx.to_owned(),
            Some(DefaultHome {
                target_id: target_id.to_owned(),
                url: url.to_owned(),
                created: false,
            }),
        ));
    }
    // no page in the default context: open one there (no `browserContextId`) and read the
    // context id it landed in
    let made = client
        .call("Target.createTarget", None, json!({ "url": "about:blank" }))
        .await?;
    let target_id = made
        .get("targetId")
        .and_then(Value::as_str)
        .ok_or_else(|| BrowserError::Protocol {
            method: "Target.createTarget".to_owned(),
            message: "no targetId".to_owned(),
        })?
        .to_owned();
    let info = client
        .call("Target.getTargetInfo", None, json!({ "targetId": target_id }))
        .await?;
    let ctx = info
        .get("targetInfo")
        .and_then(|i| i.get("browserContextId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok((
        ctx,
        Some(DefaultHome {
            target_id,
            url: "about:blank".to_owned(),
            created: true,
        }),
    ))
}

impl Drop for CdpContext {
    fn drop(&mut self) {
        self.pump.abort();
        if self.closed {
            return;
        }
        self.uncount_session();
        if !self.ctl.owns_context {
            return;
        }
        // best effort: the browser process dies with the backend, but a long-lived backend
        // must not accumulate abandoned contexts
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let client = self.ctl.client.clone();
            let id = self.ctl.browser_context_id.clone();
            handle.spawn(async move {
                let _ = client
                    .call(
                        "Target.disposeBrowserContext",
                        None,
                        json!({ "browserContextId": id }),
                    )
                    .await;
            });
        }
    }
}

/// The main-world init scripts `config` asks for, in install order: the stealth patches
/// (`dynamic.stealthPatches`), the behaviour hooks (`dynamic.pageHookOptions`) and, for tabs,
/// the discovery hooks (`dynamic.pageHooks`).
fn main_world_scripts(config: &ContextConfig, discovery: bool) -> Vec<std::borrow::Cow<'static, str>> {
    use std::borrow::Cow;
    let mut scripts = Vec::new();
    if config.stealth_patches {
        scripts.push(Cow::Owned(crate::stealth::script(&config.locale)));
    }
    if let Some(script) = hooks::behavior_script(config.page_hook_options) {
        scripts.push(Cow::Owned(script));
    }
    if discovery && config.page_hooks {
        scripts.push(Cow::Borrowed(hooks::PAGE_HOOKS_SCRIPT));
    }
    if config.captcha.is_some() {
        scripts.push(Cow::Borrowed(captcha::INIT));
    }
    scripts
}

/// Attach to `target_id`, enable the domains the adapter needs and install the observer.
/// Domains follow the profile: `Runtime`/`Console` only under `Standard` with console
/// capture, never under `Stealth`.
pub(crate) async fn setup_tab(
    ctl: &Arc<Ctl>,
    state: &Arc<Mutex<State>>,
    target_id: &str,
) -> Result<(), BrowserError> {
    let attached = ctl
        .client
        .call(
            "Target.attachToTarget",
            None,
            json!({ "targetId": target_id, "flatten": true }),
        )
        .await?;
    let session = attached
        .get("sessionId")
        .and_then(Value::as_str)
        .ok_or_else(|| BrowserError::Protocol {
            method: "Target.attachToTarget".to_owned(),
            message: "no sessionId".to_owned(),
        })?
        .to_owned();
    let sess = CdpSession {
        client: ctl.client.clone(),
        session_id: session.clone(),
    };
    let frames = sess.frame_tree().await?;
    let main = frames.first().cloned().ok_or_else(|| BrowserError::Protocol {
        method: "Page.getFrameTree".to_owned(),
        message: "empty frame tree".to_owned(),
    })?;
    {
        let mut st = state.lock();
        st.attaching.remove(target_id);
        let mut tab = Tab::new(target_id, &session, &main.id, &main.url, Instant::now());
        // a popup's first load may already be under way
        tab.loading = false;
        st.tabs.insert(target_id.to_owned(), tab);
    }
    sess.send("Page.enable", json!({})).await?;
    sess.send("Page.setLifecycleEventsEnabled", json!({ "enabled": true }))
        .await?;
    // A popup may have committed its first navigation before the session was attached;
    // re-read the frame tree so the tab starts with its real URL.
    if let Some(main) = sess.frame_tree().await?.first() {
        let mut st = state.lock();
        if let Some(t) = st.tabs.get_mut(target_id) {
            if t.url != main.url {
                t.url.clone_from(&main.url);
                t.main_frame.clone_from(&main.id);
            }
        }
        st.graph.set_url(target_id, &main.url);
    }
    sess.send("Network.enable", capture::network_params()).await?;
    sess.send("DOM.enable", json!({})).await?;
    sess.send("Accessibility.enable", json!({})).await?;
    if ctl.behavior.enable_runtime {
        sess.send("Runtime.enable", json!({})).await?;
    }
    let vp = ctl.config.viewport;
    sess.send(
        "Emulation.setDeviceMetricsOverride",
        json!({ "width": vp.width, "height": vp.height, "deviceScaleFactor": 1, "mobile": false }),
    )
    .await?;
    apply_request_controls(&sess, ctl).await?;
    if let Some(navigation_guard) = &ctl.config.navigation_guard {
        // Native acquisition additionally reserves one allowance per actual subresource.
        let patterns = if navigation_guard.intercepts_subresources() {
            json!([{ "requestStage": "Request" }])
        } else {
            guard::patterns()
        };
        sess.fetch_enable(patterns).await?;
    }
    // Some builds reject a second locale override; the `--lang` flag already sets the default.
    let _ = sess
        .send(
            "Emulation.setLocaleOverride",
            json!({ "locale": ctl.config.locale }),
        )
        .await;
    page_ops::apply_overrides(&sess, ctl, state, page_ops::SessionKind::Tab).await?;
    sess.send(
        "Page.addScriptToEvaluateOnNewDocument",
        json!({ "source": js::OBSERVER, "worldName": js::WORLD_NAME, "runImmediately": true }),
    )
    .await?;
    for script in main_world_scripts(&ctl.config, true) {
        // main world on purpose: the scripts wrap the page's own `fetch`/`history`/`navigator`
        // objects (see `hooks`, `stealth`); `runImmediately` covers an adopted page that
        // already has a document
        sess.send(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": script, "runImmediately": true }),
        )
        .await?;
    }
    // Out-of-process iframes become their own flattened sessions (`Target.attachedToTarget`
    // on this session); they start paused so `setup_frame` enables their domains before any
    // request of theirs goes unobserved.
    sess.send("Target.setAutoAttach", auto_attach_params()).await?;
    // Service-worker versions belong to browser targets, not a page's frame tree.
    // Scope browser-level auto-attachment to this tab; never pause unrelated contexts.
    ctl.client
        .call(
            "Target.autoAttachRelated",
            None,
            json!({
                "targetId": target_id,
                "waitForDebuggerOnStart": true,
                "filter": [
                    { "type": "service_worker", "exclude": false },
                    { "exclude": true }
                ]
            }),
        )
        .await?;
    Ok(())
}

/// `Target.setAutoAttach` parameters shared by the tab and its child frames (nested frames):
/// iframe targets, paused until their capture domains are enabled.
fn auto_attach_params() -> Value {
    json!({
        "autoAttach": true,
        "waitForDebuggerOnStart": true,
        "flatten": true,
        "filter": [
            { "type": "iframe", "exclude": false },
            { "exclude": true }
        ]
    })
}

/// Apply the run's request controls to one tab or child-frame session: the extra request
/// headers (`Network.setExtraHTTPHeaders`), `Security.setIgnoreCertificateErrors` under
/// `fetch.skipTlsVerification`, and the `User-Agent` (`fetch.userAgent`, else
/// `ContextConfig::user_agent`) through `Emulation.setUserAgentOverride`. Every session
/// needs its own call: an out-of-process frame runs in its own renderer with its own
/// overrides. Cookies are not sent here; see `CdpContext::seed_request_cookies`.
///
/// Extra headers go on every request of the session, third-party subresources included,
/// as the compatibility `-H` flag and the compatibility API's `headers` do; the URL plane's fetcher scopes them to the
/// seed's registrable domain instead. A popup's first document request leaves before its
/// session attaches and so carries neither headers nor the override.
///
/// # Errors
/// The protocol error of the first command Chromium rejects: a configured control is never
/// dropped silently.
async fn apply_request_controls(sess: &CdpSession, ctl: &Ctl) -> Result<(), BrowserError> {
    let controls = &ctl.config.request_controls;
    if !controls.headers().is_empty() {
        let headers: serde_json::Map<String, Value> = controls
            .headers()
            .iter()
            .map(|(name, value)| (name.clone(), json!(value.expose())))
            .collect();
        sess.send("Network.setExtraHTTPHeaders", json!({ "headers": headers }))
            .await?;
    }
    if controls.skip_tls_verification() {
        sess.send("Security.setIgnoreCertificateErrors", json!({ "ignore": true }))
            .await?;
    }
    if let Some(ua) = controls.user_agent().or(ctl.config.user_agent.as_deref()) {
        sess.send(
            "Emulation.setUserAgentOverride",
            json!({ "userAgent": ua, "acceptLanguage": ctl.config.locale }),
        )
        .await?;
    }
    Ok(())
}

/// CDP `domain` of a control cookie: a leading dot makes a domain cookie (the host and its
/// subdomains, like the fetch plane); an IP literal or a single-label host can only be
/// host-only.
fn cookie_domain(domain: &str) -> String {
    let bare = domain.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() || !bare.contains('.') {
        bare.to_owned()
    } else {
        format!(".{bare}")
    }
}

/// Enable the observation and input domains on an auto-attached child-frame session, ask it
/// to attach its own out-of-process children, then resume it. Mutation observers and page
/// hooks are not installed: epochs and the discovery sink are the main frame's.
async fn setup_frame(
    ctl: &Arc<Ctl>,
    state: &Arc<Mutex<State>>,
    target_id: &str,
    session: &str,
) -> Result<(), BrowserError> {
    let sess = CdpSession {
        client: ctl.client.clone(),
        session_id: session.to_owned(),
    };
    let enabled = async {
        sess.send("Page.enable", json!({})).await?;
        sess.send("Network.enable", capture::network_params()).await?;
        apply_request_controls(&sess, ctl).await?;
        // the frame's first document does not exist yet: the scripts run when it is created
        for script in main_world_scripts(&ctl.config, false) {
            sess.send(
                "Page.addScriptToEvaluateOnNewDocument",
                json!({ "source": script }),
            )
            .await?;
        }
        page_ops::apply_overrides(&sess, ctl, state, page_ops::SessionKind::Frame).await?;
        sess.send("DOM.enable", json!({})).await?;
        sess.send("Accessibility.enable", json!({})).await?;
        if ctl.behavior.enable_runtime {
            sess.send("Runtime.enable", json!({})).await?;
        }
        sess.send("Target.setAutoAttach", auto_attach_params()).await
    }
    .await;
    // the frame resumes whatever the setup did: a paused frame would hang its page
    let resumed = sess.send("Runtime.runIfWaitingForDebugger", json!({})).await;
    {
        let mut st = state.lock();
        if let Some(f) = st
            .tabs
            .get_mut(target_id)
            .and_then(|t| t.frames.values_mut().find(|f| f.session == session))
        {
            f.ready = true;
        }
    }
    enabled.and(resumed).map(|_| ())
}

async fn pump(ctl: Arc<Ctl>, state: Arc<Mutex<State>>, mut rx: broadcast::Receiver<Arc<CdpEvent>>) {
    let mut jobs = tokio::task::JoinSet::new();
    loop {
        let received = tokio::select! {
            result = rx.recv() => result,
            _ = jobs.join_next(), if !jobs.is_empty() => continue,
        };
        let ev = match received {
            Ok(ev) => ev,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    skipped = n,
                    "CDP event pump lagged; traffic capture may be incomplete"
                );
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => break,
        };
        if ev.method == "crawlx.connectionClosed" {
            // a context alive when the DevTools connection drops lost its browser
            count_crash("disconnected");
            state.lock().closed = true;
            ctl.notify.send_modify(|v| *v = v.wrapping_add(1));
            break;
        }
        if ev.method == "Fetch.requestPaused" {
            // only a context with a guard enables `Fetch`; the broadcast also carries the
            // events of other contexts, which their own pumps answer. Answered off the pump: the
            // guard may need the network (a `robots.txt` fetch) and the pump must keep folding
            // events meanwhile
            if ctl.config.navigation_guard.is_some() {
                tokio::spawn(crawlx_core::custody::inherit(guard::answer_paused(
                    Arc::clone(&ctl),
                    Arc::clone(&state),
                    Arc::clone(&ev),
                )));
            }
            continue;
        }
        // the broadcast carries every context's events: count a crash only when it marked
        // one of this context's tabs
        let crash_event = ev.method == "Target.targetCrashed" || ev.method == "Inspector.targetCrashed";
        let followups = {
            let mut st = state.lock();
            let crashed_before = crash_event.then(|| st.tabs.values().filter(|t| t.crashed).count());
            let followups = st.handle_event(&ev, Instant::now(), ctl.shared.clock.now());
            if crashed_before.is_some_and(|before| st.tabs.values().filter(|t| t.crashed).count() > before) {
                count_crash("target_crashed");
            }
            followups
        };
        ctl.notify.send_modify(|v| *v = v.wrapping_add(1));
        for f in followups {
            let ctl = Arc::clone(&ctl);
            let state = Arc::clone(&state);
            jobs.spawn(crawlx_core::custody::inherit(async move {
                match f {
                    Followup::AttachPopup { target_id } => {
                        match setup_tab(&ctl, &state, &target_id).await {
                            Ok(()) => {
                                guard::guard_popup(&ctl, &state, &target_id).await;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to attach popup; closing it");
                                let _ = ctl
                                    .client
                                    .call("Target.closeTarget", None, json!({ "targetId": target_id }))
                                    .await;
                                state.lock().remove_tab(&target_id);
                            }
                        }
                        ctl.notify.send_modify(|v| *v = v.wrapping_add(1));
                    }
                    Followup::CloseTarget { target_id } => {
                        let _ = ctl
                            .client
                            .call("Target.closeTarget", None, json!({ "targetId": target_id }))
                            .await;
                    }
                    Followup::HandleDialog { session, accept } => {
                        let _ = ctl
                            .client
                            .call(
                                "Page.handleJavaScriptDialog",
                                Some(&session),
                                json!({ "accept": accept }),
                            )
                            .await;
                    }
                    Followup::SetupFrame { target_id, session } => {
                        if let Err(e) = setup_frame(&ctl, &state, &target_id, &session).await {
                            if ctl.config.request_controls.is_empty() {
                                tracing::debug!(error = %e, "child frame setup incomplete");
                            } else {
                                // a frame that missed its request controls loads without them
                                tracing::warn!(error = %e, "child frame setup incomplete");
                            }
                        }
                        ctl.notify.send_modify(|v| *v = v.wrapping_add(1));
                    }
                    Followup::CaptureBody {
                        session,
                        request_id,
                        seq,
                        content_type,
                    } => {
                        capture::retain(&ctl, &state, &session, &request_id, seq, &content_type).await;
                    }
                    Followup::SetupWorker { session } => {
                        // Service workers have no Page/DOM domains. Enable Network before resuming.
                        let enabled = ctl
                            .client
                            .call("Network.enable", Some(&session), capture::network_params())
                            .await
                            .is_ok();
                        if !enabled {
                            tracing::warn!("service-worker network capture unavailable");
                        }
                        let _ = ctl
                            .client
                            .call("Runtime.runIfWaitingForDebugger", Some(&session), json!({}))
                            .await;
                    }
                    Followup::CapturePrefix {
                        session,
                        request_id,
                        content_type,
                    } => {
                        capture::retain_prefix(&ctl, &state, &session, &request_id, &content_type).await;
                    }
                    Followup::ResumeTarget { session } => {
                        let _ = ctl
                            .client
                            .call("Runtime.runIfWaitingForDebugger", Some(&session), json!({}))
                            .await;
                    }
                }
            }));
        }
    }
}

#[async_trait]
impl BrowserContext for CdpContext {
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        let result = self
            .navigate_to(url.url.as_str())
            .await
            .map_err(|error| self.mask_captcha_error(error))?;
        self.mask_captcha(result)
    }

    async fn captcha_pending(&mut self) -> Result<bool, BrowserError> {
        self.has_captcha().await
    }

    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        self.observe_impl(spec)
            .await
            .map_err(|error| self.mask_captcha_error(error))
    }

    async fn revalidate(
        &mut self,
        locator: &RuntimeLocator,
        expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        match self
            .revalidate_impl(locator, expected)
            .await
            .map_err(|error| self.mask_captcha_error(error))?
        {
            Revalidation::Actionable { live } => Ok(Revalidation::Actionable {
                live: self.mask_captcha(live)?,
            }),
            other => Ok(other),
        }
    }

    async fn resolve_selector(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, BrowserError> {
        self.resolve_selector_impl(selector).await
    }

    async fn perform(&mut self, action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        let receipt = self
            .perform_impl(action)
            .await
            .map_err(|error| self.mask_captcha_error(error))?;
        self.mask_captcha(receipt)
    }

    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        let report = self.settle_impl(policy).await?;
        capture::flush(&self.ctl, &self.state).await;
        Ok(report)
    }

    fn current_epoch(&self) -> ObservationEpoch {
        self.state
            .lock()
            .active_tab()
            .map(|t| t.epoch)
            .unwrap_or_default()
    }

    fn drain_traffic(&mut self) -> Vec<TrafficEvent> {
        let traffic = {
            let mut state = self.state.lock();
            let first_pending = state.pending_bodies.first().copied();
            let ready = state
                .traffic
                .iter()
                .take_while(|event| first_pending.is_none_or(|seq| event.seq < seq))
                .count();
            state.traffic.drain(..ready).collect()
        };
        self.mask_captcha(traffic).unwrap_or_default()
    }

    fn drain_xhr(&mut self) -> Vec<crawlx_core::dom_ops::XhrRecord> {
        let xhr = self.state.lock().drain_xhr();
        self.mask_captcha(xhr).unwrap_or_default()
    }

    fn drain_blocked_navigations(&mut self) -> Vec<crawlx_core::browser::BlockedNavigation> {
        self.state
            .lock()
            .take_blocked_navigations()
            .into_iter()
            .map(|mut blocked| {
                blocked.url = self
                    .ctl
                    .config
                    .captcha_secrets
                    .redact(&blocked.url)
                    .unwrap_or_else(|_| "[REDACTED]".to_owned());
                blocked
            })
            .collect()
    }

    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError> {
        self.export_storage_impl().await
    }

    async fn import_storage(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        self.import_storage_impl(blob).await
    }

    async fn close(mut self: Box<Self>) -> Result<(), BrowserError> {
        if self.virtual_rows.is_some() {
            tracing::info!(stop = ?crawlx_core::dom_ops::VirtualRowsStop::Interrupted,
                "virtual rows collection stopped during context cleanup");
        }
        let restoration = self.restore_virtual_rows().await;
        let disposed = self.dispose().await;
        disposed?;
        match restoration? {
            crawlx_core::dom_ops::VirtualRowsRestoration::Restored
            | crawlx_core::dom_ops::VirtualRowsRestoration::Inactive => Ok(()),
            _ => Err(BrowserError::Script(
                "virtual rows restoration failed during close".into(),
            )),
        }
    }

    async fn lazy_scroll(
        &mut self,
        spec: crawlx_core::dom_ops::LazyScrollSpec,
    ) -> Result<crawlx_core::dom_ops::LazyScrollReport, BrowserError> {
        self.lazy_scroll_impl(spec).await
    }

    async fn css_filter(
        &mut self,
        filter: &crawlx_core::dom_ops::CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, BrowserError> {
        self.css_filter_impl(filter, targets).await
    }

    async fn page_op(
        &mut self,
        op: crawlx_core::page_op::PageOp,
    ) -> Result<crawlx_core::page_op::PageOpResult, BrowserError> {
        self.page_op_impl(op)
            .await
            .map_err(|error| self.mask_captcha_error(error))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::cookie_domain;

    #[test]
    fn cookie_domains_are_domain_cookies_only_for_dotted_names() {
        // a registrable domain covers its subdomains, like the fetch plane's matching
        assert_eq!(cookie_domain("example.test"), ".example.test");
        assert_eq!(cookie_domain("www.example.co.uk"), ".www.example.co.uk");
        // an IP literal and a single-label host can only be host-only cookies
        assert_eq!(cookie_domain("127.0.0.1"), "127.0.0.1");
        assert_eq!(cookie_domain("localhost"), "localhost");
        assert_eq!(cookie_domain("[::1]"), "::1");
    }
}
