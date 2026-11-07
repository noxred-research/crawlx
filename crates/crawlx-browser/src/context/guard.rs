//! The navigation guard in the real browser (`ContextConfig::navigation_guard`).
//!
//! Two paths consult it, both before a document request can reach the network:
//!
//! * the context's own navigations (`navigate`, a `Navigate` action) ask the guard before
//!   `Page.navigate` is sent;
//! * every main-frame document request a page issues itself (a clicked link, a form submit, a
//!   script's `location` change, each redirect hop) is paused with `Fetch.requestPaused`
//!   (stage `Request`, resource type `Document`) and either continued or failed with
//!   `Aborted`. `Aborted` cancels the navigation without an error page, so the current
//!   document stays and the next observation still sees the page the action started from.
//!
//! Subresources and the documents of embedded frames are never paused for a verdict: the guard
//! is about what the crawler *visits*, and the URL plane does not apply `robots.txt` to them
//! either. Frame sessions therefore do not enable `Fetch` at all.
//!
//! Popups attach after their first request may have left (the same ordering limit as the
//! request controls, see `apply_request_controls`): a popup whose URL the guard refuses is
//! closed as soon as it attaches and recorded like any other refusal; its later navigations go
//! through the paused-request path above.

use super::{Ctl, State};
use crate::cdp::{CdpEvent, CdpSession};
use crawlx_core::browser::{BlockedNavigation, BrowserError, NavigationGuard};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Longest a guard may take to decide. A guard that does not answer fails closed: the request
/// is refused instead of left paused, which would hang the page.
const GUARD_TIMEOUT: Duration = Duration::from_secs(30);

/// Reason recorded when the guard does not answer in time.
const TIMEOUT_REASON: &str = "robots_unavailable";

/// `Fetch.enable` patterns: document requests only, paused before they are sent.
pub(crate) fn patterns() -> Value {
    json!([{ "resourceType": "Document", "requestStage": "Request" }])
}

/// The URL as the guard sees and the journal records it: no credentials, no fragment.
pub(crate) fn loggable(url: &Url) -> String {
    let mut plain = url.clone();
    let _ = plain.set_username("");
    let _ = plain.set_password(None);
    plain.set_fragment(None);
    plain.into()
}

/// The reason code when `guard` refuses `url`, `None` when the navigation may go ahead.
/// A guard that takes longer than [`GUARD_TIMEOUT`] refuses.
pub(crate) async fn refusal(guard: &dyn NavigationGuard, url: &Url) -> Option<&'static str> {
    match tokio::time::timeout(GUARD_TIMEOUT, guard.check(url)).await {
        Ok(verdict) => verdict.refusal(),
        Err(_) => Some(TIMEOUT_REASON),
    }
}

/// Only `http` and `https` documents are the guard's business; `about:`, `data:`, `blob:` and
/// error pages load no remote document, and every other scheme is refused by the egress layer.
fn guarded(raw: &str) -> Option<Url> {
    Url::parse(raw)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Answer one `Fetch.requestPaused` event: continue it, or fail it when it is a main-frame
/// document request the guard refuses. The broadcast carries every context's events, so an
/// event of a session this context does not own is left to its owner.
pub(crate) async fn answer_paused(ctl: Arc<Ctl>, state: Arc<Mutex<State>>, ev: Arc<CdpEvent>) {
    let Some(session) = ev.session_id.as_deref() else {
        return;
    };
    let request_id = text(&ev.params, "requestId");
    if request_id.is_empty() {
        return;
    }
    let (target_id, main_frame) = {
        let st = state.lock();
        match st.tabs.values().find(|t| t.session == session) {
            Some(tab) => (tab.target_id.clone(), tab.main_frame.clone()),
            None => return,
        }
    };
    let sess = CdpSession {
        client: ctl.client.clone(),
        session_id: session.to_owned(),
    };
    let main_document =
        text(&ev.params, "resourceType") == "Document" && text(&ev.params, "frameId") == main_frame;
    let url = ev
        .params
        .get("request")
        .map(|request| text(request, "url"))
        .and_then(guarded)
        .filter(|_| {
            main_document
                || ctl
                    .config
                    .navigation_guard
                    .as_ref()
                    .is_some_and(|guard| guard.intercepts_subresources())
        });
    let refused = match (ctl.config.navigation_guard.as_ref(), url.as_ref()) {
        (Some(guard), Some(url)) => match tokio::time::timeout(GUARD_TIMEOUT, async {
            if main_document {
                guard.check_request(url).await
            } else {
                guard.check_subresource(url).await
            }
        })
        .await
        {
            Ok(verdict) => verdict.refusal(),
            Err(_) => Some(TIMEOUT_REASON),
        },
        _ => None,
    };
    let Some(reason) = refused else {
        // a failure here means the page went away with its request: nothing left to resume
        let _ = sess
            .send("Fetch.continueRequest", json!({ "requestId": request_id }))
            .await;
        return;
    };
    if let Some(url) = url.as_ref().filter(|_| main_document) {
        // recorded before the request fails, so the navigation that waits on it sees the refusal
        state
            .lock()
            .record_blocked_navigation(&target_id, BlockedNavigation::new(loggable(url), reason));
        ctl.notify.send_modify(|v| *v = v.wrapping_add(1));
    }
    let _ = sess
        .send(
            "Fetch.failRequest",
            json!({ "requestId": request_id, "errorReason": "Aborted" }),
        )
        .await;
}

/// A popup that attached: close it when the guard refuses the document it already shows.
/// Returns whether it was closed.
pub(crate) async fn guard_popup(ctl: &Arc<Ctl>, state: &Arc<Mutex<State>>, target_id: &str) -> bool {
    let Some(guard) = ctl.config.navigation_guard.as_ref() else {
        return false;
    };
    let shown = state.lock().tabs.get(target_id).map(|tab| tab.url.clone());
    let Some(url) = shown.as_deref().and_then(guarded) else {
        return false;
    };
    let Some(reason) = refusal(guard.as_ref(), &url).await else {
        return false;
    };
    state
        .lock()
        .record_blocked_navigation(target_id, BlockedNavigation::new(loggable(&url), reason));
    let _ = ctl
        .client
        .call("Target.closeTarget", None, json!({ "targetId": target_id }))
        .await;
    state.lock().remove_tab(target_id);
    ctl.notify.send_modify(|v| *v = v.wrapping_add(1));
    true
}

/// The refusal of the context's own navigation to `url`, as the error `navigate` returns.
///
/// # Errors
/// [`BrowserError::RobotsBlocked`] or [`BrowserError::EgressDenied`] when the guard refuses `url`.
pub(crate) async fn check_navigation(
    guard: Option<&Arc<dyn NavigationGuard>>,
    url: &Url,
) -> Result<(), BrowserError> {
    let Some(guard) = guard else {
        return Ok(());
    };
    match refusal(guard.as_ref(), url).await {
        None => Ok(()),
        Some(reason) => Err(BlockedNavigation::new(loggable(url), reason).into_error()),
    }
}
