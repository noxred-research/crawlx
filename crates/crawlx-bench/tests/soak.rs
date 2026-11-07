//! Public soak admission refuses missing trusted gates before output, database or browser setup.
//! The authored two-worker execution fixture lives in `soak`'s private unit-test module;
//! it exercises cycles and reports without claiming measured deployment evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::soak::parse_duration;
use std::time::Duration;

#[test]
fn durations_parse() {
    assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
    assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
    assert_eq!(parse_duration("1h30m5s").unwrap(), Duration::from_secs(5405));
    assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
    assert!(parse_duration("").is_err());
    assert!(parse_duration("5x").is_err());
    assert!(parse_duration("h").is_err());
    assert!(parse_duration("5m3").is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn subprocess_missing_trusted_gates_refuses_before_output_schema_or_browser() {
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    let root = tempfile::tempdir().unwrap();
    let gates = root.path().join("gates");
    std::fs::create_dir(&gates).unwrap();
    let browser = root.path().join("chromium");
    let browser_started = root.path().join("browser-started");
    std::fs::write(
        &browser,
        "#!/bin/sh\nprintf launched > \"$SOAK_TEST_BROWSER_STARTED\"\nexit 99\n",
    )
    .unwrap();
    std::fs::set_permissions(&browser, std::fs::Permissions::from_mode(0o700)).unwrap();

    // No database connection means admission cannot create or migrate a schema.
    let database = TcpListener::bind("127.0.0.1:0").unwrap();
    database.set_nonblocking(true).unwrap();
    let database_url = format!("postgres://soak:soak@{}/soak", database.local_addr().unwrap());
    for fake in [false, true] {
        let out = root.path().join(if fake { "fake-out" } else { "chromium-out" });
        let mut command = Command::new(env!("CARGO_BIN_EXE_soak"));
        command
            .args(["--duration", "8s", "--workers", "2", "--fixtures", "g01,g02"])
            .arg("--database-url")
            .arg(&database_url)
            .arg("--out")
            .arg(&out)
            .env("CRAWLX_GATES_DIR", &gates)
            .env_remove("CRAWLX_GATE_KEYS_FILE")
            .env_remove("CRAWLX_GATE_KEY_ID")
            .env("CRAWLX_CHROMIUM_PATH", &browser)
            .env("SOAK_TEST_BROWSER_STARTED", &browser_started);
        if fake {
            command.arg("--fake");
        }
        let result = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(2), "fake={fake}: {stderr}");
        for reason in ["state_novelty", "G1", "CRAWLX_GATE_KEYS_FILE"] {
            assert!(stderr.contains(reason), "fake={fake}: missing {reason}: {stderr}");
        }
        assert!(result.stdout.is_empty(), "refusal must not emit a soak report");
        assert!(!out.exists(), "admission created output: {}", out.display());
        assert!(!browser_started.exists(), "admission launched Chromium");
        match database.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("database connection sentinel failed: {error}"),
            Ok(_) => panic!("admission connected to PostgreSQL before validating gates"),
        }
    }
}
