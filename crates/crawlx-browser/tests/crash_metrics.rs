//! `crawlx.browser.crashes{reason}` through fake actions and real Chromium events.
//! Fake actions count only under `action`; renderer crashes and browser disconnects count
//! once per affected target under their own bounded reasons. Real tests explicitly skip
//! when `CRAWLX_CHROMIUM_PATH` is unset. The registry is process-global, so every assertion
//! is a delta and the tests are serialized.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use crawlx_browser::cdp::CdpClient;
use crawlx_browser::fake::{action_key, FakeAxSpec, FakePage, FakeScript};
use crawlx_browser::{ChromiumBackend, FakeBackend, LaunchConfig};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, BrowserContext, BrowserError, ContextConfig};
use crawlx_core::identity::ActionKind;
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationBundle, ObservationSpec, RuntimeLocator};
use crawlx_core::url::CanonicalUrl;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use serde_json::json;
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

async fn real_browser() -> Option<(ChromiumBackend, tempfile::TempDir, CdpClient)> {
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("SKIP: CRAWLX_CHROMIUM_PATH is unset; real crash metrics require Chromium");
        return None;
    };
    let profile = tempfile::tempdir().unwrap();
    let mut config = LaunchConfig::new();
    config.executable = executable.into();
    config.user_data_dir = Some(profile.path().to_path_buf());
    config.allow_unpinned = true;
    let backend = ChromiumBackend::launch(config)
        .await
        .expect("chromium must launch");

    // Use a separate real DevTools connection: the context exposes no raw CDP command API.
    let endpoint = tokio::fs::read_to_string(profile.path().join("DevToolsActivePort"))
        .await
        .unwrap();
    let mut lines = endpoint.lines();
    let port: u16 = lines.next().unwrap().parse().unwrap();
    let ws_url = format!("ws://127.0.0.1:{port}{}", lines.next().unwrap());
    let client = CdpClient::connect(&ws_url).await.unwrap();
    client
        .call("Target.setDiscoverTargets", None, json!({ "discover": true }))
        .await
        .unwrap();
    Some((backend, profile, client))
}

async fn crash_targets(client: &CdpClient, targets: &[String]) {
    let mut events = client.subscribe();
    let processes = client
        .call("SystemInfo.getProcessInfo", None, json!({}))
        .await
        .unwrap();
    let renderers: Vec<u32> = processes["processInfo"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|process| process["type"] == "renderer")
        .map(|process| u32::try_from(process["id"].as_i64().unwrap()).unwrap())
        .collect();
    assert!(!renderers.is_empty());
    // Kill only renderer PIDs reported by this owned browser. Unlike Page.crash, SIGKILL
    // cannot block on an overloaded host's core-dump handler. CDP still emits real target
    // crash notifications; no event or counter is injected.
    for pid in renderers {
        let result = tokio::process::Command::new("kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .status()
            .await
            .unwrap();
        assert!(result.success(), "owned renderer {pid} must terminate");
    }
    let mut remaining: std::collections::BTreeSet<_> = targets.iter().cloned().collect();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !remaining.is_empty() {
            let event = events.recv().await.unwrap();
            if event.method == "Target.targetCrashed" {
                if let Some(target) = event.params["targetId"].as_str() {
                    remaining.remove(target);
                }
            }
        }
    })
    .await
    .expect("chromium must emit crash events for the owned targets");
}

async fn wait_for_crashes(reason: &str, expected: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while crashes(reason) < expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("context event pumps must account for the real browser event");
    assert_eq!(crashes(reason), expected);
}

#[tokio::test]
async fn real_target_crashes_count_once_per_target_without_action_counts() {
    let _serial = SERIAL.lock().await;
    let Some((backend, _profile, client)) = real_browser().await else {
        return;
    };
    let before = (
        crashes("action"),
        crashes("target_crashed"),
        crashes("disconnected"),
    );
    let first = backend
        .new_cdp_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    let second = backend
        .new_cdp_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    assert_eq!(first.evaluate_isolated("1 + 1").await.unwrap(), json!(2));
    assert_eq!(second.evaluate_isolated("1 + 1").await.unwrap(), json!(2));
    assert_eq!(crashes("action"), before.0);
    assert_eq!(crashes("target_crashed"), before.1);
    assert_eq!(crashes("disconnected"), before.2);

    // Both pumps see both browser-wide crash events. Each owner counts its own target,
    // and Target/Inspector notifications must not double-count the same renderer exit.
    let targets: Vec<String> = first.tab_ids().into_iter().chain(second.tab_ids()).collect();
    assert_eq!(targets.len(), 2);
    crash_targets(&client, &targets).await;
    wait_for_crashes("target_crashed", before.1 + 2).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(crashes("target_crashed"), before.1 + 2);
    assert_eq!(crashes("action"), before.0);
    assert_eq!(crashes("disconnected"), before.2);

    Box::new(first).close().await.unwrap();
    Box::new(second).close().await.unwrap();
    backend.shutdown().await;
    assert_eq!(crashes("target_crashed"), before.1 + 2);
    assert_eq!(crashes("action"), before.0);
    assert_eq!(crashes("disconnected"), before.2);
}

#[tokio::test]
async fn real_browser_disconnect_counts_once_per_live_target_without_action_counts() {
    let _serial = SERIAL.lock().await;
    let Some((backend, _profile, client)) = real_browser().await else {
        return;
    };
    let before = (
        crashes("action"),
        crashes("target_crashed"),
        crashes("disconnected"),
    );
    let first = backend
        .new_cdp_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    let second = backend
        .new_cdp_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    assert_eq!(first.tab_ids().len(), 1);
    assert_eq!(second.tab_ids().len(), 1);
    assert_eq!(first.evaluate_isolated("1 + 1").await.unwrap(), json!(2));
    assert_eq!(second.evaluate_isolated("1 + 1").await.unwrap(), json!(2));
    assert_eq!(crashes("disconnected"), before.2);

    // Keep both contexts alive while Browser.close terminates the actual browser.
    backend.shutdown().await;
    wait_for_crashes("disconnected", before.2 + 2).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !client.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the real DevTools connection must close");
    assert!(first.evaluate_isolated("1 + 1").await.is_err());
    assert!(second.evaluate_isolated("1 + 1").await.is_err());
    backend.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(crashes("disconnected"), before.2 + 2);
    assert_eq!(crashes("target_crashed"), before.1);
    assert_eq!(crashes("action"), before.0);
    Box::new(first).close().await.unwrap();
    Box::new(second).close().await.unwrap();
}
