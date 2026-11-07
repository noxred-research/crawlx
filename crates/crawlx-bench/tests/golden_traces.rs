//! Golden-trace comparison on a pin bump (identity stability).
//!
//! `fixtures/golden/traces/g03.json` is the derived trace (state signature, identity hashes,
//! candidate counts, action outcomes per step) of a deterministic walk over `g03` (the original
//! ARIA slice) on the pinned Chromium. This test repeats the walk on the running Chromium and
//! compares step by step. `CRAWLX_BLESS=1` re-records the golden instead. The diff is written
//! to `bench/out/golden-trace-diff.g03.json`; the `chromium-next` job uploads it as the
//! pin-bump review artifact.
//!
//! The gym is bound to the port recorded in the golden so the origin-bearing signature
//! fields compare too; if that port is taken the walk runs on a free port and those two
//! fields are excluded (reported in the diff as `origin_comparable: false`).
//!
//! Skips (with a message) without a Chromium (`CRAWLX_CHROMIUM_PATH` or a usual location).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::golden::{self, GoldenTrace};
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserBackend, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::ids::SessionId;
use std::net::SocketAddr;
use std::path::PathBuf;

const FIXTURE: &str = "g03";

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("fixtures/golden/traces/{FIXTURE}.json"))
}

fn diff_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../bench/out/golden-trace-diff.{FIXTURE}.json"))
}

async fn launch() -> Option<ChromiumBackend> {
    let exe = find_executable()?;
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.launch_profile = LaunchProfile::Standard;
    cfg.allow_unpinned = true;
    match ChromiumBackend::launch(cfg.clone()).await {
        Ok(b) => Some(b),
        Err(first) => {
            eprintln!(
                "warning: launch failed ({first}); retrying once with --no-sandbox (CI containers only)"
            );
            cfg.unsafe_no_sandbox_for_ci = true;
            Some(ChromiumBackend::launch(cfg).await.expect("chromium must launch"))
        }
    }
}

/// The gym on the golden's port when it is free, otherwise on any port.
async fn gym_for(golden: Option<&GoldenTrace>) -> (crawlx_bench::gym::GymHandle, bool) {
    if let Some(g) = golden {
        let addr: Option<SocketAddr> = g.base_url.strip_prefix("http://").and_then(|a| a.parse().ok());
        if let Some(addr) = addr {
            if let Ok(h) = GymServer::start(addr).await {
                return (h, true);
            }
            eprintln!("golden port {addr} is busy; origin-bearing signature fields will not be compared");
        }
    }
    (
        GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap(),
        false,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g03_derived_trace_matches_the_golden_recorded_on_the_pinned_build() {
    let Some(backend) = launch().await else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let bless = std::env::var_os("CRAWLX_BLESS").is_some_and(|v| v == "1");
    let path = golden_path();
    let golden = if path.exists() {
        Some(GoldenTrace::load(&path).unwrap())
    } else {
        None
    };
    if golden.is_none() && !bless {
        panic!(
            "{} is missing; record it on the pinned Chromium with CRAWLX_BLESS=1",
            path.display()
        );
    }
    let (gym, origin_comparable) = gym_for(golden.as_ref()).await;
    let manifest = FixtureManifest::embedded(FIXTURE).unwrap();
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    let build = backend.build_info().clone();
    let fresh = golden::record(ctx.as_mut(), &manifest, &gym.base_url, &build)
        .await
        .unwrap();
    ctx.close().await.unwrap();
    gym.shutdown().await;
    assert_eq!(fresh.steps.len(), manifest.controls.len() + 1);
    assert!(
        fresh.steps.iter().filter(|s| s.action.is_some()).count() >= manifest.controls.len() / 2,
        "most controls must be clickable: {:#?}",
        fresh
            .steps
            .iter()
            .filter_map(|s| s.skipped.as_ref())
            .collect::<Vec<_>>()
    );
    if bless {
        fresh.save(&path).unwrap();
        eprintln!(
            "blessed {} on Chromium {} (pinned: {})",
            path.display(),
            build.chromium_version,
            build.pinned
        );
        return;
    }
    let golden = golden.unwrap();
    let diff = golden::diff(&golden, &fresh, origin_comparable);
    let out = diff_path();
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, serde_json::to_string_pretty(&diff).unwrap()).unwrap();
    eprintln!(
        "golden Chromium {} (pinned: {}) vs running {} (pinned: {}): {} differing steps of {}; report {}",
        golden.recorded_with.chromium_version,
        golden.recorded_with.pinned,
        build.chromium_version,
        build.pinned,
        diff.steps.len(),
        golden.steps.len(),
        out.display()
    );
    assert!(
        diff.is_clean(),
        "derived trace differs from the golden:\n{}",
        diff.summary()
    );
}
