#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! SDK-in-the-loop shape diff of the real, self-hosted Firecrawl against the crawlx facade
//! (see `docs/integrations.md`).
//!
//! Gated on the environment: without `CRAWLX_UPSTREAM_FIRECRAWL_URL` the test prints `skipping:
//! ...` and returns, so `cargo test` stays offline-green. With it, the same official `firecrawl-py`
//! calls (`bench/differential/sdk_shape_capture.py`: scrape, scrape of a 404 and of a
//! robots-disallowed page, map, start_crawl + get_crawl_status + get_crawl_errors, the crawl
//! waiter, cancel_crawl) run once against the real Firecrawl and once against the in-process
//! facade (`support/sdk_rig.rs`), both crawling the same CrawlerGym fixture `s1`, and
//! `bench/differential/sdk_shape_diff.py` writes the field-by-field report.
//!
//! Environment:
//!
//! * `CRAWLX_UPSTREAM_FIRECRAWL_URL`: the Firecrawl API, e.g. `http://127.0.0.1:3102` (a no-auth
//!   self-host; its containers reach the gym as `gym.test`, see `bench/differential/`);
//! * `CRAWLX_UPSTREAM_GYM_PORT`: the port of a running CrawlerGym server (default 4100). It listens
//!   on all interfaces: the host reaches it as `127.0.0.1:PORT` (the rig maps `site.example.test`
//!   there), Firecrawl as `http://gym.test:PORT`;
//! * `CRAWLX_SDK_SHAPE_OUT`: where the captures and `sdk-shape-diff.md` go (default
//!   `bench/out/sdk-shape`, relative to the repository root);
//! * `CRAWLX_SDK_SHAPE_EVIDENCE`: optional directory that also receives the size-trimmed captures
//!   (`upstream.json`, `crawlx.json`);
//! * `CRAWLX_UPSTREAM_COMMIT`: the pinned Firecrawl commit, named in the report header;
//! * `CRAWLX_SDK_PYTHONPATH`: an installed `pip install --target` directory of
//!   `tests/sdk/requirements.txt` (else it is installed, like `sdk_python.rs`; an unavailable pip
//!   or PyPI skips the test).

#[path = "support/sdk_install.rs"]
mod sdk_install;
#[path = "support/sdk_rig.rs"]
#[allow(dead_code)]
mod sdk_rig;

use sdk_install::{install_python_sdk, pinned_python_sdk, repo_root};
use sdk_rig::{SdkRig, Site};
use serde_json::Value;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Budget of one capture script (a crawl of the whole fixture polls until done).
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(900);
/// The fixture the capture crawls, on both sides.
const FIXTURE: &str = "s1";
/// What the report is required to have an entry for, on both sides (the shape-diff acceptance set).
const CALLS: [&str; 9] = [
    "scrape",
    "scrape_404",
    "scrape_robots_disallowed",
    "map",
    "start_crawl",
    "get_crawl_status",
    "get_crawl_errors",
    "crawl",
    "cancel_crawl",
];

/// Run a Python script of `bench/differential` with the installed SDK on its path.
async fn run_python(label: &str, script: &str, args: &[&str], python_path: &Path) {
    let mut cmd = Command::new("python3");
    cmd.arg(repo_root().join("bench/differential").join(script))
        .args(args)
        .env("PYTHONPATH", python_path)
        .env("PYTHONUNBUFFERED", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env_remove("FIRECRAWL_API_KEY")
        .env_remove("FIRECRAWL_API_URL")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let out = tokio::time::timeout(CAPTURE_TIMEOUT, cmd.output())
        .await
        .unwrap_or_else(|_| panic!("{label} ran longer than {CAPTURE_TIMEOUT:?}"))
        .unwrap_or_else(|e| panic!("{label} could not be started: {e}"));
    println!(
        "--- {label} stdout ---\n{}\n--- {label} stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{label} failed: {}", out.status);
}

/// `path` as a UTF-8 command-line argument.
fn arg(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// The capture a script wrote.
fn read_capture(path: &Path) -> Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("no capture at {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

/// The capture is the pinned SDK's and holds every required call with a raw wire exchange; the
/// first scrape must have succeeded through the SDK (a failing facade is a finding, not a skip).
fn assert_capture(capture: &Value, label: &str, sdk_version: &str) {
    assert_eq!(capture["label"], label);
    assert_eq!(capture["sdk_version"], sdk_version, "{label}: the pinned SDK ran");
    for call in CALLS {
        let c = &capture["calls"][call];
        assert!(c.is_object(), "{label}: no capture of {call}");
        let raw = c["raw"]
            .as_array()
            .unwrap_or_else(|| panic!("{label}: {call} has no raw wire"));
        assert!(!raw.is_empty(), "{label}: {call} has no raw exchange");
        assert!(
            raw.iter().all(|e| e["status"].is_u64()),
            "{label}: {call} raw exchange without an HTTP status"
        );
    }
    assert_eq!(
        capture["calls"]["scrape"]["sdk"]["ok"], true,
        "{label}: the SDK scrape of the fixture home page failed: {}",
        capture["calls"]["scrape"]["sdk"]
    );
}

#[tokio::test]
async fn sdk_shape_diff_of_the_real_firecrawl_and_the_facade() {
    let Ok(upstream_url) = std::env::var("CRAWLX_UPSTREAM_FIRECRAWL_URL") else {
        println!("skipping: CRAWLX_UPSTREAM_FIRECRAWL_URL not set");
        return;
    };
    let gym_port: u16 = std::env::var("CRAWLX_UPSTREAM_GYM_PORT")
        .map(|p| p.parse().expect("CRAWLX_UPSTREAM_GYM_PORT is a port"))
        .unwrap_or(4100);
    let gym: SocketAddr = ([127, 0, 0, 1], gym_port).into();
    TcpStream::connect_timeout(&gym, Duration::from_secs(3))
        .unwrap_or_else(|e| panic!("the gym is not listening on {gym}: {e}"));
    let reachable = reqwest::Client::new()
        .get(&upstream_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    assert!(
        reachable.is_ok(),
        "CRAWLX_UPSTREAM_FIRECRAWL_URL={upstream_url} does not answer: {:?}",
        reachable.err()
    );

    let dir = tempfile::tempdir().unwrap();
    let python_path = match std::env::var_os("CRAWLX_SDK_PYTHONPATH") {
        Some(p) => PathBuf::from(p),
        None => {
            if let Err(why) = install_python_sdk(dir.path()).await {
                println!("skipping: {why}");
                return;
            }
            dir.path().to_path_buf()
        }
    };

    let out_dir = std::env::var_os("CRAWLX_SDK_SHAPE_OUT").map_or_else(
        || repo_root().join("bench/out/sdk-shape"),
        |p| repo_root().join(p),
    );
    std::fs::create_dir_all(&out_dir).unwrap();
    let upstream_out = out_dir.join("upstream.json");
    let crawlx_out = out_dir.join("crawlx.json");
    let report = out_dir.join("sdk-shape-diff.md");
    // a stale capture of an earlier run must not satisfy the assertions below
    for stale in [&upstream_out, &crawlx_out, &report] {
        let _ = std::fs::remove_file(stale);
    }

    // the real Firecrawl: its containers reach the gym as `gym.test`
    let gym_origin = format!("http://gym.test:{gym_port}");
    run_python(
        "upstream capture",
        "sdk_shape_capture.py",
        &[
            "--api",
            &upstream_url,
            "--site",
            &gym_origin,
            "--fixture",
            FIXTURE,
            "--label",
            "upstream",
            "--out",
            arg(&upstream_out),
        ],
        &python_path,
    )
    .await;

    // the facade, in-process, crawling the very same gym through the rig's host name
    let rig = SdkRig::start_with_site(Site::external(gym_port)).await;
    let site_origin = rig.site.url("");
    run_python(
        "crawlx capture",
        "sdk_shape_capture.py",
        &[
            "--api",
            &rig.rewritten_root,
            "--site",
            &site_origin,
            "--fixture",
            FIXTURE,
            "--label",
            "crawlx",
            "--key",
            &rig.key,
            "--out",
            arg(&crawlx_out),
        ],
        &python_path,
    )
    .await;
    rig.stop().await;

    let sdk_version = pinned_python_sdk();
    assert_capture(&read_capture(&upstream_out), "upstream", &sdk_version);
    assert_capture(&read_capture(&crawlx_out), "crawlx", &sdk_version);

    let commit = std::env::var("CRAWLX_UPSTREAM_COMMIT").unwrap_or_else(|_| "not given".to_owned());
    let meta_commit = format!("upstream commit={commit}");
    let meta_gym = format!("gym port={gym_port}");
    let mut args = vec![
        "--upstream",
        arg(&upstream_out),
        "--crawlx",
        arg(&crawlx_out),
        "--out",
        arg(&report),
        "--meta",
        meta_commit.as_str(),
        "--meta",
        meta_gym.as_str(),
    ];
    let evidence = std::env::var_os("CRAWLX_SDK_SHAPE_EVIDENCE").map(|p| repo_root().join(p));
    if let Some(evidence) = &evidence {
        args.extend(["--evidence-dir", arg(evidence)]);
    }
    run_python("shape diff", "sdk_shape_diff.py", &args, &python_path).await;

    let text = std::fs::read_to_string(&report).expect("the diff wrote its report");
    assert!(text.starts_with("# SDK shape diff"), "{text}");
    for call in CALLS {
        assert!(
            text.contains(&format!("## `{call}`")),
            "the report has no section for {call}"
        );
    }
    println!("report: {}", report.display());
}
