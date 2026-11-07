//! Live `cdp-surface.toml` compatibility checks against the pinned browser.
//! `ci/lint-static.sh` owns source/catalog synchronization; this suite probes actual
//! command availability. The `chromium-next` job runs it against Stable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::cdp::CdpClient;
use crawlx_browser::launch::{self, find_executable};
use crawlx_browser::{ChromiumPin, LaunchConfig};
use crawlx_core::browser::BrowserError;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const SURFACE: &str = include_str!("../../../cdp-surface.toml");
const PIN: &str = include_str!("../../../chromium-pin.toml");

#[derive(Deserialize)]
struct Surface {
    chromium: SurfaceChromium,
    commands: Vec<Command>,
}

#[derive(Deserialize)]
struct SurfaceChromium {
    version: String,
    cdp_revision: String,
}

#[derive(Deserialize)]
struct Command {
    name: String,
    requires: Requires,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum Requires {
    Browser,
    Page,
    Skip,
}

fn surface() -> Surface {
    toml::from_str(SURFACE).expect("cdp-surface.toml parses")
}

#[test]
fn cdp_surface_tracks_the_pinned_build() {
    let s = surface();
    let pin = ChromiumPin::parse(PIN).unwrap();
    assert_eq!(s.chromium.version, pin.version);
    assert_eq!(s.chromium.cdp_revision, pin.cdp_revision);
}

#[tokio::test]
async fn cdp_surface_commands_exist_on_the_running_build() {
    if find_executable().is_none() {
        eprintln!("skipped: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let s = surface();
    let config = LaunchConfig::new();
    let tmp = tempfile::Builder::new()
        .prefix("crawlx-cdp-surface-")
        .tempdir()
        .unwrap();
    let dir = tmp.path().to_path_buf();
    let mut spawned = launch::spawn(&config, Some(tmp), dir).await.unwrap();
    let client = CdpClient::connect(&spawned.ws_url).await.unwrap();

    let version = client.call("Browser.getVersion", None, json!({})).await.unwrap();
    let product = version["product"].as_str().unwrap_or("").to_owned();
    let protocol = version["protocolVersion"].as_str().unwrap_or("").to_owned();
    eprintln!("cdp-surface against {product} (protocol {protocol})");
    assert_eq!(protocol, s.chromium.cdp_revision, "CDP protocol revision drifted");

    let target = client
        .call("Target.createTarget", None, json!({ "url": "about:blank" }))
        .await
        .unwrap();
    let target_id = target["targetId"].as_str().unwrap().to_owned();
    let attached = client
        .call(
            "Target.attachToTarget",
            None,
            json!({ "targetId": target_id, "flatten": true }),
        )
        .await
        .unwrap();
    let session = attached["sessionId"].as_str().unwrap().to_owned();

    let mut not_found = Vec::new();
    for c in &s.commands {
        let sid = match c.requires {
            Requires::Skip => continue,
            Requires::Browser => None,
            Requires::Page => Some(session.as_str()),
        };
        let params = c.params.clone().unwrap_or_else(|| json!({}));
        let result = client
            .call_with_timeout(&c.name, sid, params, Duration::from_secs(10))
            .await;
        match result {
            Ok(_) => {}
            // an answer other than "method not found" proves the method exists on this build
            Err(BrowserError::Protocol { message, .. }) if message.contains("wasn't found") => {
                not_found.push(format!("{}: {message}", c.name));
            }
            Err(BrowserError::Protocol { .. }) => {}
            Err(e) => panic!("{}: unexpected transport failure: {e}", c.name),
        }
    }
    assert!(
        not_found.is_empty(),
        "methods missing on {product}: {not_found:#?}"
    );

    let _ = client
        .call("Target.closeTarget", None, json!({ "targetId": target_id }))
        .await;
    let _ = client
        .call_with_timeout("Browser.close", None, json!({}), Duration::from_secs(5))
        .await;
    spawned.process.shutdown(Duration::from_secs(3)).await;
}
