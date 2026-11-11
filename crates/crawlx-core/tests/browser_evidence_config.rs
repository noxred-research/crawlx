//! Browser evidence admission preserves hard bounds and retention restrictions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::CreateCrawl;

fn request(capture: serde_json::Value, mode: &str, retention: &str) -> CreateCrawl {
    serde_json::from_value(serde_json::json!({
        "seedUrl": "https://site.test/", "mode": mode,
        "retention": {"mode": retention}, "capture": {"browser": capture},
    }))
    .unwrap()
}

#[test]
fn bounded_browser_capture_round_trips_and_static_mode_cannot_silently_ignore_it() {
    let config = serde_json::json!({
        "xhr": {"urlPatterns": ["https://site.test/api/*"], "maxRecords": 2, "maxBytes": 8192},
        "diagnostics": {"maxRecords": 4, "maxBytes": 8192},
        "mhtml": true, "phaseResources": true,
    });
    let mut dynamic = request(config.clone(), "dynamic", "standard");
    dynamic.normalize().unwrap();
    let roundtrip: CreateCrawl = serde_json::from_value(serde_json::to_value(&dynamic).unwrap()).unwrap();
    assert_eq!(dynamic.capture.browser, roundtrip.capture.browser);
    assert!(request(config.clone(), "static", "standard").normalize().is_err());
    assert!(request(config, "dynamic", "zdr").normalize().is_err());
}

#[test]
fn invalid_projection_or_download_limits_fail_before_browser_work() {
    for config in [
        serde_json::json!({"xhr": {"urlPatterns": [], "maxRecords": 1, "maxBytes": 1}}),
        serde_json::json!({"xhr": {"urlPatterns": ["*"], "maxRecords": 0, "maxBytes": 1}}),
        serde_json::json!({"diagnostics": {"maxRecords": 5001, "maxBytes": 1}}),
        serde_json::json!({"diagnostics": {"maxRecords": 1, "maxBytes": 8388609}}),
        serde_json::json!({"downloads": [{"url": "file:///tmp/private", "maxBytes": 1, "timeoutMs": 1}]}),
        serde_json::json!({"downloads": [{"url": "https://site.test/file", "maxBytes": 16777217, "timeoutMs": 1}]}),
        serde_json::json!({"downloads": [{"url": "https://site.test/file", "maxBytes": 1, "timeoutMs": 120001}]}),
    ] {
        assert!(
            request(config.clone(), "dynamic", "standard")
                .normalize()
                .is_err(),
            "{config}"
        );
    }
}

#[test]
fn metadata_projection_remains_available_in_zdr_without_implying_retained_bodies() {
    let mut input = request(
        serde_json::json!({
            "xhr": {"urlPatterns": ["https://site.test/api/*"], "maxRecords": 2, "maxBytes": 8192},
        }),
        "dynamic",
        "zdr",
    );
    input.normalize().unwrap();
    assert!(!input.capture.browser.durable());
    assert_eq!(
        input.capture.response_bodies,
        crawlx_core::config::ResponseBodies::MetadataOnly
    );
}
