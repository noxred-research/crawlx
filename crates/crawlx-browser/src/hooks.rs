//! Browser-plane discovery hooks (`dynamic.pageHooks`): an init script that
//! records navigation sinks (`history.pushState` / `replaceState`, `window.open`,
//! `hashchange`, `WebSocket`, `EventSource`, `fetch`, `XMLHttpRequest.open`) and every
//! `addEventListener` call on an element into a sink the adapter drains after each
//! observation ([`DiscoverySink`]).
//!
//! Ported from an MIT-licensed upstream (see THIRD_PARTY_NOTICES.md): its page-init script
//! (`hookNavigatedLinkSinks`, `hookAddEventListener`). Not part of this
//! discovery script, by decision: the `setTimeout`/`setInterval` speed-up, the
//! `form.reset` and `window.close` overrides (they change application behaviour under test).
//! They exist as the opt-in [`behavior_script`] (`dynamic.pageHookOptions`),
//! never installed unless asked for. The discovery hooks never dispatch events,
//! never alter return values and never touch timing.
//!
//! The script runs in the page's **main world** (`Page.addScriptToEvaluateOnNewDocument`
//! without `worldName`): the objects it wraps (`window.fetch`, `history.pushState`,
//! `Element.prototype.addEventListener`) are per-world, so an isolated-world copy would never
//! see the page's calls. That is why the option is off by default, refused under `Stealth`
//! and why sessions crawled with it are tagged `page_hooks = true`. The sink is
//! read back with `Runtime.evaluate` in the main world (no `Runtime.enable` needed) through a
//! non-enumerable, non-writable drain function.

use crawlx_core::config::PageHookOptions;
use serde::Deserialize;

/// Name of the main-world drain function the script installs on `window`.
pub const DRAIN_FUNCTION: &str = "__crawlxDrainDiscovery";

/// Cap on entries the sink keeps between drains (per kind); older entries are dropped.
pub const SINK_CAP: usize = 2000;

/// Upper bound on listener candidates mapped to backend node ids per drain.
pub const LISTENER_MAP_BUDGET: usize = 64;

/// The init script. Installed once per document with `Page.addScriptToEvaluateOnNewDocument`
/// (`runImmediately: true`); idempotent (a second run is a no-op).
pub const PAGE_HOOKS_SCRIPT: &str = r#"(function crawlxPageHooks() {
  if (Object.prototype.hasOwnProperty.call(window, '__crawlxDrainDiscovery')) { return; }
  var CAP = 2000;
  var navigated = [];
  var listeners = [];
  function pushNav(url, source) {
    try {
      if (url == null) { return; }
      if (navigated.length >= CAP) { navigated.shift(); }
      navigated.push({ url: String(url), source: source });
    } catch (_) {}
  }
  function cssPath(el) {
    var parts = [];
    var node = el;
    while (node && node.nodeType === 1 && node !== document.documentElement) {
      var part = node.localName;
      if (node.id && typeof node.id === 'string' && /^[A-Za-z_][\w-]*$/.test(node.id)) {
        parts.unshift('#' + node.id);
        return parts.join(' > ');
      }
      var parent = node.parentElement;
      if (parent) {
        var index = 1;
        var sib = node.previousElementSibling;
        while (sib) { if (sib.localName === node.localName) { index++; } sib = sib.previousElementSibling; }
        part += ':nth-of-type(' + index + ')';
      }
      parts.unshift(part);
      node = parent;
    }
    if (node === document.documentElement) { parts.unshift('html'); }
    return parts.join(' > ');
  }
  function hookNavigatedLinkSinks() {
    var origPushState = window.history.pushState.bind(window.history);
    var origReplaceState = window.history.replaceState.bind(window.history);
    Object.defineProperty(window.history, 'pushState', { value: function (a, b, c) {
      pushNav(c, 'history.pushState'); return origPushState(a, b, c);
    }, writable: false, configurable: false });
    Object.defineProperty(window.history, 'replaceState', { value: function (a, b, c) {
      pushNav(c, 'history.replaceState'); return origReplaceState(a, b, c);
    }, writable: false, configurable: false });
    var origOpen = window.open.bind(window);
    Object.defineProperty(window, 'open', { value: function (url) {
      pushNav(url, 'window.open'); return origOpen.apply(window, arguments);
    }, writable: false, configurable: false });
    window.addEventListener('hashchange', function () { pushNav(document.location.href, 'hashchange'); });
    var OrigWebSocket = window.WebSocket;
    if (OrigWebSocket) {
      function WrappedWebSocket(url, protocols) {
        pushNav(url, 'websocket');
        return Reflect.construct(OrigWebSocket, arguments, new.target || WrappedWebSocket);
      }
      WrappedWebSocket.prototype = OrigWebSocket.prototype;
      Object.setPrototypeOf(WrappedWebSocket, OrigWebSocket);
      Object.defineProperty(window, 'WebSocket', { value: WrappedWebSocket, writable: false, configurable: false });
    }
    var OrigEventSource = window.EventSource;
    if (OrigEventSource) {
      function WrappedEventSource(url, init) {
        pushNav(url, 'eventsource');
        return Reflect.construct(OrigEventSource, arguments, new.target || WrappedEventSource);
      }
      WrappedEventSource.prototype = OrigEventSource.prototype;
      Object.setPrototypeOf(WrappedEventSource, OrigEventSource);
      Object.defineProperty(window, 'EventSource', { value: WrappedEventSource, writable: false, configurable: false });
    }
    var origFetch = window.fetch.bind(window);
    Object.defineProperty(window, 'fetch', { value: function () {
      var a = arguments[0];
      pushNav((typeof Request !== 'undefined' && a instanceof Request) ? a.url : a, 'fetch');
      return origFetch.apply(window, arguments);
    }, writable: false, configurable: false });
    var origXhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      pushNav(url, 'xhr');
      return origXhrOpen.apply(this, arguments);
    };
  }
  function hookAddEventListener() {
    var origAdd = Element.prototype.addEventListener;
    Element.prototype.addEventListener = function (type, listener, options) {
      try {
        if (this && this.tagName && this.tagName !== 'BODY' && this.tagName !== 'HTML') {
          if (listeners.length >= CAP) { listeners.shift(); }
          listeners.push({ css_path: cssPath(this), event_type: String(type), tag: this.localName });
        }
      } catch (_) {}
      return origAdd.call(this, type, listener, options);
    };
  }
  Object.defineProperty(window, '__crawlxDrainDiscovery', { value: function () {
    var out = { navigated: navigated, listeners: listeners };
    navigated = [];
    listeners = [];
    return out;
  }, writable: false, configurable: false, enumerable: false });
  try { hookAddEventListener(); } catch (_) {}
  try { hookNavigatedLinkSinks(); } catch (_) {}
})();"#;

/// Expression that drains the sink (`null` when the hooks are not installed).
pub const DRAIN_EXPRESSION: &str =
    "(typeof window.__crawlxDrainDiscovery === 'function') ? window.__crawlxDrainDiscovery() : null";

/// Template of the behaviour script; `__CRAWLX_BEHAVIOR_CONFIG__` is replaced by the JSON of
/// the active options. Main world, like [`PAGE_HOOKS_SCRIPT`], and for the same reason: the
/// objects it replaces (`window.setTimeout`, `HTMLFormElement.prototype.reset`,
/// `window.close`) are per-world.
const BEHAVIOR_SCRIPT_TEMPLATE: &str = r#"(function crawlxPageBehavior(cfg) {
  if (Object.prototype.hasOwnProperty.call(window, '__crawlxBehaviorInstalled')) { return; }
  Object.defineProperty(window, '__crawlxBehaviorInstalled', { value: true, enumerable: false });
  function define(owner, name, value) {
    try {
      Object.defineProperty(owner, name, { value: value, writable: true, configurable: true, enumerable: true });
    } catch (_) {}
  }
  if (cfg.timerDivisor >= 2) {
    var divisor = cfg.timerDivisor;
    var scale = function (delay) {
      var n = Number(delay);
      return (isFinite(n) && n > 0) ? n / divisor : delay;
    };
    var origSetTimeout = window.setTimeout;
    var origSetInterval = window.setInterval;
    define(window, 'setTimeout', function setTimeout(handler, delay) {
      var args = Array.prototype.slice.call(arguments);
      args[1] = scale(delay);
      return origSetTimeout.apply(window, args);
    });
    define(window, 'setInterval', function setInterval(handler, delay) {
      var args = Array.prototype.slice.call(arguments);
      args[1] = scale(delay);
      return origSetInterval.apply(window, args);
    });
  }
  if (cfg.preventFormReset) {
    define(HTMLFormElement.prototype, 'reset', function reset() {});
    window.addEventListener('reset', function (event) { event.preventDefault(); }, true);
  }
  if (cfg.preventWindowClose) {
    define(window, 'close', function close() {});
  }
})(__CRAWLX_BEHAVIOR_CONFIG__);"#;

/// The opt-in behaviour script for `options` (`dynamic.pageHookOptions`): timer
/// acceleration, `form.reset()` and `window.close()` prevention, the upstream page-init
/// behaviours. `None` when no option changes anything,
/// so a default configuration installs nothing.
#[must_use]
pub fn behavior_script(options: PageHookOptions) -> Option<String> {
    if !options.any() {
        return None;
    }
    let config = serde_json::json!({
        "timerDivisor": options.timer_divisor().map_or(0, u8::into),
        "preventFormReset": options.prevent_form_reset,
        "preventWindowClose": options.prevent_window_close,
    });
    Some(BEHAVIOR_SCRIPT_TEMPLATE.replace("__CRAWLX_BEHAVIOR_CONFIG__", &config.to_string()))
}

/// A navigation-sink entry.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct NavigatedUrl {
    /// The URL as the page passed it (relative URLs are not resolved).
    pub url: String,
    /// `history.pushState`, `history.replaceState`, `window.open`, `hashchange`,
    /// `websocket`, `eventsource`, `fetch` or `xhr`.
    pub source: String,
}

/// An `addEventListener` call recorded on an element.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct RecordedListener {
    /// CSS path of the element at registration time (`#id` anchored when possible).
    pub css_path: String,
    /// Event type registered.
    pub event_type: String,
    /// Element tag name.
    #[serde(default)]
    pub tag: String,
    /// Backend node id the path resolved to at drain time; `None` until mapped or when the
    /// element is gone.
    #[serde(skip)]
    pub backend_node_id: Option<i64>,
}

/// What the hooks captured since the previous drain.
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize)]
pub struct DiscoverySink {
    /// Navigation-sink entries, in capture order.
    #[serde(default)]
    pub navigated: Vec<NavigatedUrl>,
    /// Listener registrations, in capture order.
    #[serde(default)]
    pub listeners: Vec<RecordedListener>,
}

impl DiscoverySink {
    /// Parse the drain result; `null` (hooks absent) is an empty sink.
    ///
    /// # Errors
    /// Returns the serde error text when the value has an unexpected shape.
    pub fn from_value(v: &serde_json::Value) -> Result<Self, String> {
        if v.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(v.clone()).map_err(|e| e.to_string())
    }

    /// Is there nothing to report?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.navigated.is_empty() && self.listeners.is_empty()
    }

    /// Navigation entries as `(url, source)` pairs for `ObservationBundle::discovered_urls`.
    #[must_use]
    pub fn urls(&self) -> Vec<(String, String)> {
        self.navigated
            .iter()
            .map(|n| (n.url.clone(), n.source.clone()))
            .collect()
    }

    /// Distinct CSS paths of listeners whose event type is one of `interaction_events`,
    /// in first-seen order and capped at [`LISTENER_MAP_BUDGET`].
    #[must_use]
    pub fn candidate_paths(&self, interaction_events: &[&str]) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for l in &self.listeners {
            if !interaction_events.contains(&l.event_type.as_str()) || l.css_path.is_empty() {
                continue;
            }
            if !out.contains(&l.css_path.as_str()) {
                out.push(l.css_path.as_str());
                if out.len() >= LISTENER_MAP_BUDGET {
                    break;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn script_hooks_only_the_adopted_sinks() {
        for needle in [
            "history.pushState",
            "history.replaceState",
            "window.open",
            "hashchange",
            "websocket",
            "eventsource",
            "'fetch'",
            "XMLHttpRequest.prototype.open",
            "Element.prototype.addEventListener",
            DRAIN_FUNCTION,
        ] {
            assert!(PAGE_HOOKS_SCRIPT.contains(needle), "{needle}");
        }
        // not in the discovery script (the opt-in `behavior_script` carries them): timer
        // acceleration, form reset / window.close overrides, and nothing dispatches events
        // or logs
        for forbidden in [
            "setTimeout",
            "setInterval",
            "reset",
            "window.close",
            "dispatchEvent",
            "console.log",
            "click()",
        ] {
            assert!(!PAGE_HOOKS_SCRIPT.contains(forbidden), "{forbidden}");
        }
        assert!(DRAIN_EXPRESSION.contains(DRAIN_FUNCTION));
    }

    #[test]
    fn behavior_script_is_none_unless_an_option_changes_behaviour() {
        assert!(behavior_script(PageHookOptions::default()).is_none());
        let one = PageHookOptions {
            timer_acceleration: 1,
            ..PageHookOptions::default()
        };
        assert!(behavior_script(one).is_none(), "a divisor of 1 changes nothing");
        let on = PageHookOptions {
            timer_acceleration: 10,
            prevent_form_reset: true,
            prevent_window_close: false,
        };
        let script = behavior_script(on).unwrap();
        assert!(
            script.contains(r#"{"preventFormReset":true,"preventWindowClose":false,"timerDivisor":10}"#),
            "{script}"
        );
        assert!(!script.contains("__CRAWLX_BEHAVIOR_CONFIG__"));
        // the discovery script never carries them
        assert!(!PAGE_HOOKS_SCRIPT.contains("crawlxPageBehavior"));
    }

    #[test]
    fn sink_parses_and_filters() {
        let v = json!({
            "navigated": [
                {"url": "/app/1", "source": "history.pushState"},
                {"url": "/api/x", "source": "fetch"}
            ],
            "listeners": [
                {"css_path": "#card", "event_type": "click", "tag": "div"},
                {"css_path": "#card", "event_type": "mousedown", "tag": "div"},
                {"css_path": "#form", "event_type": "submit", "tag": "form"},
                {"css_path": "", "event_type": "click"}
            ]
        });
        let s = DiscoverySink::from_value(&v).unwrap();
        assert_eq!(
            s.urls(),
            vec![
                ("/app/1".to_owned(), "history.pushState".to_owned()),
                ("/api/x".to_owned(), "fetch".to_owned())
            ]
        );
        assert_eq!(s.candidate_paths(&["click", "mousedown"]), vec!["#card"]);
        assert!(!s.is_empty());
        assert!(DiscoverySink::from_value(&json!(null)).unwrap().is_empty());
        assert!(DiscoverySink::from_value(&json!({})).unwrap().is_empty());
        assert!(DiscoverySink::from_value(&json!([1])).is_err());
    }
}
