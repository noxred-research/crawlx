//! Launch options (`-ho`, `-cdd`, `-sb`, `-hc`) against a local Chromium (skipped
//! without one; set `CRAWLX_CHROMIUM_PATH`) and against a missing executable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod surface_support;

use crawlx_browser::health::{probe, HealthReport};
use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::BrowserError;
use std::path::Path;
use surface_support::{context_config, launch};

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_probe_reports_a_missing_executable_without_launching_anything() {
    let mut cfg = LaunchConfig::new();
    cfg.executable = Path::new("/nonexistent/crawlx/chromium").to_path_buf();
    let report = probe(&cfg).await;
    let names: Vec<_> = report.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "chromium_found",
            "chromium_version",
            "launch",
            "blank_page",
            "pin"
        ]
    );
    assert!(!report.ok());
    let found = report.check("chromium_found").unwrap();
    assert!(!found.ok);
    assert!(
        found.detail.contains("/nonexistent/crawlx/chromium"),
        "{}",
        found.detail
    );
    for later in ["chromium_version", "launch", "blank_page", "pin"] {
        let check = report.check(later).unwrap();
        assert!(!check.ok && check.detail.starts_with("skipped:"), "{check:?}");
    }
}

fn all_ok(report: &HealthReport) -> bool {
    report.ok() && report.checks.len() == 5
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_probe_launches_chromium_and_opens_a_blank_page() {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.allow_unpinned = true;
    let mut report = probe(&cfg).await;
    if !all_ok(&report) && report.check("launch").is_some_and(|c| !c.ok) {
        // CI containers without user namespaces: the probe's hint names the switch
        let launch = report.check("launch").unwrap();
        eprintln!(
            "warning: launch failed ({}); retrying once with --no-sandbox",
            launch.detail
        );
        cfg.unsafe_no_sandbox_for_ci = true;
        report = probe(&cfg).await;
    }
    assert!(all_ok(&report), "{report:#?}");
    assert!(report
        .check("chromium_version")
        .unwrap()
        .detail
        .to_ascii_lowercase()
        .contains("chrom"));
    assert!(report.check("launch").unwrap().detail.contains("cdp"));
    assert!(report.check("blank_page").unwrap().detail.contains("about:blank"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["checks"][0]["name"], "chromium_found");
    assert_eq!(json["checks"][0]["ok"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_probe_flags_an_unpinned_build_unless_unpinned_runs_are_allowed() {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.unsafe_no_sandbox_for_ci =
        cfg.unsafe_no_sandbox_for_ci || std::env::var("USER").is_ok_and(|u| u == "root");
    cfg.allow_unpinned = true;
    let allowed = probe(&cfg).await;
    let Some(pin) = allowed.check("pin") else {
        panic!("{allowed:#?}")
    };
    if !pin.ok || !pin.detail.contains("differs") {
        // the installed build matches chromium-pin.toml: nothing to distinguish
        return;
    }
    cfg.allow_unpinned = false;
    let strict = probe(&cfg).await;
    let pin = strict.check("pin").unwrap();
    assert!(!pin.ok, "{pin:?}");
    assert!(pin.detail.contains("CRAWLX_ALLOW_UNPINNED"), "{}", pin.detail);
    assert!(!strict.ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_options_reach_chromium() {
    let mut options = LaunchConfig::new();
    options
        .add_headless_options(&strings(&["--user-agent=crawlx-ho-test/1", "--disable-gpu"]))
        .unwrap();
    let extra = options.extra_args.clone();
    let Some(backend) = launch(None, |cfg| cfg.extra_args.clone_from(&extra)).await else {
        return;
    };
    assert!(backend
        .launch_flags()
        .contains(&"--user-agent=crawlx-ho-test/1".to_owned()));
    let ctx = backend.new_cdp_context(context_config()).await.unwrap();
    let ua = ctx.evaluate_isolated("navigator.userAgent").await.unwrap();
    assert_eq!(ua, "crawlx-ho-test/1", "the -ho switch changed the browser");
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_headless_options_never_reach_a_launched_browser() {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    for refused in [
        "--proxy-server=http://203.0.113.9:3128",
        "--remote-debugging-port=9333",
        "--disable-web-security",
        "--no-sandbox",
    ] {
        // bypassing the validated setter by writing the field is caught at launch
        let mut cfg = LaunchConfig::new();
        cfg.executable.clone_from(&exe);
        cfg.allow_unpinned = true;
        cfg.extra_args.push(refused.to_owned());
        let err = ChromiumBackend::launch(cfg).await.err().expect("must be refused");
        assert!(
            matches!(&err, BrowserError::Launch(m) if m.contains("refused")),
            "{refused}: {err}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chrome_data_dir_keeps_the_profile_after_the_browser_exits() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join("profile");
    let mut cfg = LaunchConfig::new();
    cfg.set_user_data_dir(&profile).unwrap();
    let wanted = cfg.user_data_dir.clone();
    let Some(backend) = launch(None, |c| c.user_data_dir.clone_from(&wanted)).await else {
        return;
    };
    assert!(backend
        .launch_flags()
        .contains(&format!("--user-data-dir={}", profile.display())));
    let ctx = backend.new_cdp_context(context_config()).await.unwrap();
    ctx.evaluate_isolated("1").await.unwrap();
    backend.close().await.unwrap();
    let entries: Vec<_> = std::fs::read_dir(&profile)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.iter().any(|n| n == "Default" || n == "Local State"),
        "Chromium wrote its profile into the requested directory (never deleted): {entries:?}"
    );
}

#[test]
fn show_browser_drops_the_headless_switch_and_nothing_else() {
    let mut cfg = LaunchConfig::new();
    cfg.headless = true;
    let headless = cfg.launch_flags(Path::new("/tmp/p"));
    cfg.headless = false;
    let shown = cfg.launch_flags(Path::new("/tmp/p"));
    assert!(headless.contains(&"--headless=new".to_owned()));
    assert!(!shown.iter().any(|f| f.starts_with("--headless")));
    let without: Vec<_> = headless
        .iter()
        .filter(|f| *f != "--headless=new")
        .cloned()
        .collect();
    assert_eq!(shown, without);
}
