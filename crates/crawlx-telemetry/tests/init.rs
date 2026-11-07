#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Global installation. One test only: the global subscriber is process-wide.

use crawlx_telemetry::{init, TelemetryConfig, TelemetryError};

#[test]
fn init_installs_once() {
    let bad = TelemetryConfig {
        filter: Some("[nope".into()),
        ..TelemetryConfig::default()
    };
    assert!(matches!(init(bad), Err(TelemetryError::InvalidFilter(_))));

    let cfg = TelemetryConfig {
        filter: Some("off".into()),
        ..TelemetryConfig::default()
    };
    let _guard = init(cfg.clone()).unwrap();
    assert!(matches!(init(cfg), Err(TelemetryError::AlreadyInitialized)));
}
