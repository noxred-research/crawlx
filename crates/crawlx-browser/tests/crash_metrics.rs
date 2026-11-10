//! `crawlx.browser.crashes{reason}` through the fake context: an action that crashes the target
//! counts under `reason = action`, other failures and healthy actions count nothing, and the
//! reasons stay inside the bounded set the catalog documents. No Chromium needed. The registry
//! is process-global, so every assertion is a delta and the tests are serialized.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{action_key, FakeAxSpec, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, BrowserError, ContextConfig};
use crawlx_core::identity::ActionKind;
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationBundle, ObservationSpec, RuntimeLocator};
use crawlx_core::url::CanonicalUrl;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use url::Url;

const HOME: &str = "https://site.test/";

/// Serializes the tests: every one asserts exact deltas on the global registry.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn crashes(reason: &str) -> u64 {
    Metrics::global()
        .counter(names::BROWSER_CRASHES)
        .get(&[("reason", reason)])
}

fn canon(s: &str) -> CanonicalUrl {
    Canonicalizer::canonicalize_url(&Url::parse(s).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

fn locator(bundle: &ObservationBundle, key: &str) -> RuntimeLocator {
    bundle
        .ax
        .nodes
        .iter()
        .find(|n| n.locator.ax_node_id.as_ref().is_some_and(|a| a.0 == key))
        .unwrap()
        .locator
        .clone()
}

fn click(target: RuntimeLocator) -> BrowserAction {
    BrowserAction::Click {
        target,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    }
}

fn script() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new(HOME)
                .title("Home")
                .node(FakeAxSpec::button("boom", "Crash the renderer"))
                .node(FakeAxSpec::button("broken", "Fails"))
                .node(FakeAxSpec::button("fine", "Works")),
        )
        .crash_on(action_key(ActionKind::Click, "boom"))
        .fail_action(action_key(ActionKind::Click, "broken"), "scripted failure")
}

#[tokio::test]
async fn a_crashing_action_counts_once_under_its_reason() {
    let _serial = SERIAL.lock().await;
    let backend = FakeBackend::new(script());
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    ctx.navigate(&canon(HOME)).await.unwrap();
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    let before = (
        crashes("action"),
        crashes("target_crashed"),
        crashes("disconnected"),
    );

    // healthy and ordinarily failing actions are not crashes
    ctx.perform(click(locator(&bundle, "fine"))).await.unwrap();
    let err = ctx.perform(click(locator(&bundle, "broken"))).await.unwrap_err();
    assert!(matches!(err, BrowserError::Script(_)), "{err:?}");
    assert_eq!(crashes("action"), before.0);

    let err = ctx.perform(click(locator(&bundle, "boom"))).await.unwrap_err();
    assert!(err.is_target_crash(), "{err:?}");
    assert_eq!(crashes("action"), before.0 + 1, "the crash is counted once");

    // a second crash adds one more; the other reasons stay where they were
    let err = ctx.perform(click(locator(&bundle, "boom"))).await.unwrap_err();
    assert!(err.is_target_crash(), "{err:?}");
    assert_eq!(crashes("action"), before.0 + 2);
    assert_eq!(crashes("target_crashed"), before.1);
    assert_eq!(crashes("disconnected"), before.2);
}

#[tokio::test]
async fn every_crash_series_uses_a_bounded_reason() {
    let _serial = SERIAL.lock().await;
    let backend = FakeBackend::new(script());
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    ctx.navigate(&canon(HOME)).await.unwrap();
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    ctx.perform(click(locator(&bundle, "boom"))).await.unwrap_err();

    let series = Metrics::global().snapshot_family(names::BROWSER_CRASHES).unwrap();
    assert!(!series.is_empty());
    for s in series {
        let reason = s
            .labels
            .iter()
            .find(|(k, _)| *k == "reason")
            .map(|(_, v)| v.as_str());
        assert!(
            matches!(reason, Some("action" | "target_crashed" | "disconnected")),
            "{:?}",
            s.labels
        );
    }
}
