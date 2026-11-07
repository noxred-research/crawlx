//! Navigation and quiescence.

use super::{record_settle, CdpContext};
use crawlx_core::browser::BrowserError;
use crawlx_core::observation::{NavigationResult, QuiescencePolicy, SettleReport};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// How long a navigation may take to fire `load` before it fails.
pub const NAVIGATION_TIMEOUT: Duration = Duration::from_secs(30);
const SETTLE_TICK: Duration = Duration::from_millis(25);

impl CdpContext {
    /// `Page.navigate` + wait for `load`; reports redirects and egress denials.
    pub(crate) async fn navigate_to(&mut self, url: &str) -> Result<NavigationResult, BrowserError> {
        // Only http(s) may be loaded: `file:`, `javascript:`, `chrome:` and friends never
        // reach the egress proxy, so the browser layer refuses them itself.
        let parsed = url::Url::parse(url).map_err(|e| BrowserError::Navigation(format!("{url}: {e}")))?;
        let scheme = parsed.scheme().to_owned();
        if let Err(e) = crawlx_policy::EgressPolicy::default().check_scheme(&scheme) {
            Metrics::global()
                .counter(names::EGRESS_DENIALS)
                .inc_by(1, &[("plane", "browser"), ("reason", "scheme")]);
            return Err(BrowserError::EgressDenied(e.to_string()));
        }
        // before anything is sent: a refused navigation never reaches the network
        super::guard::check_navigation(self.ctl.config.navigation_guard.as_ref(), &parsed).await?;
        let (target_id, sess) = self.session_for(None)?;
        {
            let mut st = self.state.lock();
            st.blocked_by_egress.clear();
            if let Some(t) = st.tabs.get_mut(&target_id) {
                t.nav_redirects.clear();
                t.nav_status = None;
                t.nav_response = None;
                t.nav_blocked = None;
                t.open_network_epoch();
            }
        }
        let started_nav = self
            .state
            .lock()
            .tabs
            .get(&target_id)
            .map(|t| t.epoch.navigation_seq)
            .unwrap_or_default();
        let r = sess.send("Page.navigate", json!({ "url": url })).await?;
        // a redirect hop the guard refused ends the navigation here, as an aborted load
        self.refused_navigation(&target_id)?;
        if let Some(err) = r
            .get("errorText")
            .and_then(Value::as_str)
            .filter(|e| !e.is_empty())
        {
            let proxied =
                self.ctl.shared.egress_proxy_port.is_some() || self.ctl.config.egress_proxy_port.is_some();
            return Err(if proxied && err.contains("ERR_TUNNEL_CONNECTION_FAILED") {
                BrowserError::EgressDenied(url.to_owned())
            } else {
                BrowserError::Navigation(format!("{url}: {err}"))
            });
        }
        match r.get("loaderId").and_then(Value::as_str) {
            Some(loader) => {
                let loader = loader.to_owned();
                let tid = target_id.clone();
                self.wait_until(NAVIGATION_TIMEOUT, move |st| {
                    st.tabs
                        .get(&tid)
                        .is_none_or(|t| t.loaded.contains(&loader) || t.nav_blocked.is_some())
                })
                .await?;
            }
            None => {
                // same-document navigation, download or 204: nothing will load
                let tid = target_id.clone();
                let _ = self
                    .wait_until(Duration::from_millis(500), move |st| {
                        st.tabs
                            .get(&tid)
                            .is_some_and(|t| t.epoch.navigation_seq > started_nav || !t.loading)
                    })
                    .await;
            }
        }
        self.refused_navigation(&target_id)?;
        self.finish_navigation(&target_id).await
    }

    /// The refusal that ended the navigation in flight on `target_id`, as the error `navigate`
    /// returns; the navigation's refusal is not reported a second time through
    /// [`BrowserContext::drain_blocked_navigations`](crawlx_core::BrowserContext::drain_blocked_navigations).
    fn refused_navigation(&self, target_id: &str) -> Result<(), BrowserError> {
        match self.state.lock().take_nav_blocked(target_id) {
            Some(blocked) => Err(blocked.into_error()),
            None => Ok(()),
        }
    }

    async fn finish_navigation(&mut self, target_id: &str) -> Result<NavigationResult, BrowserError> {
        // Refresh the observer counters of the new document; a failure here only means the
        // document is not scriptable (e.g. an error page), which is not a navigation failure.
        if let Err(e) = self.poll_counters(None).await {
            if e.is_target_crash() {
                return Err(e);
            }
        }
        let mut st = self.state.lock();
        let blocked = st.blocked_by_egress.clone();
        let t = st.tabs.get_mut(target_id).ok_or(BrowserError::TargetClosed)?;
        t.perform_done_at = Instant::now();
        t.last_net = t.last_net.max(t.perform_done_at);
        Ok(NavigationResult {
            final_url: t.url.clone(),
            status: t.nav_status,
            epoch: t.epoch,
            network_epoch: t.net_epoch,
            redirects: t.nav_redirects.clone(),
            blocked_by_egress: blocked,
        })
    }

    /// Wait for quiescence: an unconditional `fixed_wait_ms` first (page-load presets),
    /// then no blocking requests for the network window, no mutations for
    /// the mutation window, navigation not pending, bounded by the hard timeout.
    pub(crate) async fn settle_impl(
        &mut self,
        policy: QuiescencePolicy,
    ) -> Result<SettleReport, BrowserError> {
        let started = Instant::now();
        if policy.fixed_wait_ms > 0 {
            tokio::time::sleep(Duration::from_millis(policy.fixed_wait_ms)).await;
        }
        let deadline = Instant::now() + Duration::from_millis(policy.hard_timeout_ms);
        let net_window = Duration::from_millis(policy.network_idle_window_ms);
        let mut_window = Duration::from_millis(policy.mutation_idle_window_ms);
        let (target_id, _) = self.session_for(None)?;
        // t0 is the perform/navigation completion time, not zero: it is what catches fetches
        // scheduled with `setTimeout(0)` right after the action.
        let t0 = self
            .state
            .lock()
            .tabs
            .get(&target_id)
            .map(|t| t.perform_done_at)
            .unwrap_or(started)
            .min(started);

        // volatile targets seen mutating while waiting; they are excluded from mutation-idle
        let mut excluded_volatile = 0_u32;
        loop {
            // A failing poll (navigation in progress, context swapped) is retried next tick;
            // only a dead target aborts the wait.
            match self.poll_counters(None).await {
                Ok(c) => excluded_volatile = excluded_volatile.max(c.volatile_recent),
                Err(e) if e.is_target_crash() => return Err(e),
                Err(_) => {}
            }
            let now = Instant::now();
            let (inflight, last_net, last_mut, loading) = {
                let st = self.state.lock();
                let t = st.tabs.get(&target_id).ok_or(BrowserError::TargetClosed)?;
                if t.crashed {
                    return Err(BrowserError::TargetCrashed);
                }
                (
                    t.blocking_inflight(now),
                    t.last_net.max(t0),
                    t.last_stable_mut.max(t0),
                    t.loading,
                )
            };
            let network_idle = inflight == 0 && now.saturating_duration_since(last_net) >= net_window;
            let mutation_idle = now.saturating_duration_since(last_mut) >= mut_window;
            let navigation_settled = !policy.navigation_settled || !loading;
            let timed_out = now >= deadline;
            if (network_idle && mutation_idle && navigation_settled) || timed_out {
                let ok = network_idle && mutation_idle && navigation_settled;
                let report = SettleReport {
                    waited_ms: u64::try_from(now.saturating_duration_since(started).as_millis())
                        .unwrap_or(u64::MAX),
                    network_idle,
                    mutation_idle,
                    navigation_settled: !loading,
                    settle_timeout: !ok,
                    postcondition: None,
                    excluded_volatile_targets: excluded_volatile,
                };
                if let Some(t) = self.state.lock().tabs.get_mut(&target_id) {
                    t.merge_observed_methods();
                }
                record_settle(&report);
                self.last_settle = Some(report.clone());
                return Ok(report);
            }
            tokio::time::sleep(SETTLE_TICK.min(deadline.saturating_duration_since(now))).await;
        }
    }
}
