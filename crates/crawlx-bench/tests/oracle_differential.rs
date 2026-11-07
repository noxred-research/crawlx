//! Playwright/Patchright AX-recall differential.
//!
//! The Node oracle (`bench/browser-oracle/runner.mjs --discover`) enumerates the role-locator
//! elements of every catalog fixture page G01–G30 and runs the driver's actionability checks
//! on each; crawlx observes the same pages on distinct Standard and Stealth Chromium instances.
//! Each profile must independently reach >= 0.95 recall over >= 200 oracle-actionable elements.
//! Every fixture must have oracle capability parity and identical discovered/unsupported keys
//! across the two real launch profiles.
//! Both engines use one production egress proxy restricted to the gym's retained listener.
//! G29's private-network probes must be refused before any foreign destination is dialed.
//!
//! Prerequisites, each named when missing: a Chromium for crawlx (`CRAWLX_CHROMIUM_PATH` or a
//! usual location); and either an oracle result file (`CRAWLX_ORACLE_DISCOVERY=<file>`) or a
//! `node` on `PATH` plus `bench/browser-oracle/node_modules/<driver>` (`npm ci && npx
//! playwright install chromium` there) so the test can run the oracle itself against its gym.
//! `ORACLE_DRIVER` selects the driver (default `playwright`). The comparison is written to
//! `bench/browser-oracle/out/discovery-comparison.<driver>.<profile>.json`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::gym::fixtures::CATALOG_ROWS;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::oracle::discovery::{
    compare_discovery, discovery_job, element_keys, write_discovery_job, CrawlxElements, DiscoveryReport,
    MIN_ORACLE_ELEMENTS, RECALL_FLOOR,
};
use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserBackend, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationSpec, QuiescencePolicy};
use crawlx_elements::{CandidateDiscovery, DiscoveryConfig};
use crawlx_fetch::{EgressProxy, StaticResolver};
use crawlx_policy::EgressPolicy;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Catalog rows the differential covers, including G29's zero-control egress page.
const ROWS: std::ops::RangeInclusive<u32> = 1..=30;

fn oracle_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/browser-oracle")
}

fn fixtures() -> Vec<FixtureManifest> {
    CATALOG_ROWS
        .iter()
        .filter(|(row, _)| {
            let n: u32 = row.trim_start_matches('G').parse().unwrap();
            ROWS.contains(&n)
        })
        .map(|(_, id)| FixtureManifest::embedded(id).unwrap())
        .collect()
}

/// The oracle report: from `CRAWLX_ORACLE_DISCOVERY`, or produced now by the Node runner.
fn oracle_report(job_path: &Path, driver: &str, proxy: &str) -> Result<DiscoveryReport, String> {
    if let Some(path) = std::env::var_os("CRAWLX_ORACLE_DISCOVERY") {
        return DiscoveryReport::load(Path::new(&path))
            .map_err(|e| format!("{e}: {}", Path::new(&path).display()));
    }
    let dir = oracle_dir();
    if !dir
        .join("node_modules")
        .join(driver)
        .join("package.json")
        .exists()
    {
        return Err(format!(
            "bench/browser-oracle/node_modules/{driver} is absent (run `npm ci && npx {driver} install chromium` there) and CRAWLX_ORACLE_DISCOVERY is unset"
        ));
    }
    let out = dir.join("out").join(format!("discovery.{driver}.json"));
    let mut cmd = std::process::Command::new("node");
    cmd.arg("runner.mjs")
        .arg("--discover")
        .arg(job_path)
        .arg("--proxy")
        .arg(proxy)
        .arg("--out")
        .arg(&out)
        .current_dir(&dir)
        .env("ORACLE_DRIVER", driver);
    let status = cmd.status().map_err(|e| format!("cannot run `node` ({e})"))?;
    if !status.success() {
        return Err(format!("node runner.mjs --discover exited with {status}"));
    }
    DiscoveryReport::load(&out).map_err(|e| format!("{e}: {}", out.display()))
}

fn canonical(url: &str) -> crawlx_core::url::CanonicalUrl {
    Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ax_recall_and_capability_parity_against_the_oracle() {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let driver = std::env::var("ORACLE_DRIVER").unwrap_or_else(|_| "playwright".to_owned());
    let gym = GymServer::start_evaluation().await.unwrap();
    let scope = gym
        .evaluation_scope()
        .expect("gym must retain a live fixture listener");
    let origin = scope.origin().clone();
    let origin_port = origin.port().unwrap();
    let mut policy = EgressPolicy::new(true);
    policy.extra_allow = vec!["127.0.0.1/32".parse().unwrap()];
    policy.extra_ports = vec![origin_port];
    policy.fixture_scope = Some(scope);
    let proxy = EgressProxy::serve(Arc::new(policy), Arc::new(StaticResolver::new()))
        .await
        .unwrap();
    let proxy_port = proxy.port();
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let manifests = fixtures();
    let job = discovery_job(&manifests, origin.as_str().trim_end_matches('/'));
    let job_path = oracle_dir().join("out").join("discovery-job.json");
    write_discovery_job(&job, &job_path).unwrap();

    // The oracle runs first (a blocking child process); its keys do not depend on the port.
    let job_file = job_path.clone();
    let driver_name = driver.clone();
    let report = match tokio::task::spawn_blocking(move || oracle_report(&job_file, &driver_name, &proxy_url))
        .await
        .unwrap()
    {
        Ok(r) => r,
        Err(reason) => {
            eprintln!("SKIP: oracle discovery unavailable: {reason}");
            proxy.shutdown().await;
            gym.shutdown().await;
            return;
        }
    };
    let expected: std::collections::BTreeSet<_> =
        job.fixtures.iter().map(|fixture| fixture.id.as_str()).collect();
    let observed: std::collections::BTreeSet<_> = report
        .fixtures
        .iter()
        .map(|fixture| fixture.id.as_str())
        .collect();
    assert_eq!(
        observed, expected,
        "oracle report must cover every G01–G30 fixture, including zero-control G29"
    );
    assert_eq!(
        report.fixtures.len(),
        job.fixtures.len(),
        "duplicate oracle fixture rows"
    );

    let mut profiles = Vec::new();
    for profile in [LaunchProfile::Standard, LaunchProfile::Stealth] {
        // crawlx's side: the same pages, the same settle, the default discovery ladder.
        let mut cfg = LaunchConfig::new();
        cfg.executable = exe.clone();
        cfg.launch_profile = profile;
        cfg.allow_unpinned = true;
        cfg.egress_proxy_port = Some(proxy_port);
        let backend = match ChromiumBackend::launch(cfg.clone()).await {
            Ok(b) => b,
            Err(first) => {
                eprintln!(
                    "warning: launch failed ({first}); retrying once with --no-sandbox (CI containers only)"
                );
                cfg.unsafe_no_sandbox_for_ci = true;
                ChromiumBackend::launch(cfg).await.expect("chromium must launch")
            }
        };
        let mut ours: BTreeMap<String, CrawlxElements> = BTreeMap::new();
        for fx in &job.fixtures {
            let mut context = ContextConfig::new(SessionId::new());
            context.launch_profile = profile;
            context.egress_proxy_port = Some(proxy_port);
            let mut ctx = backend.new_context(context).await.unwrap();
            ctx.navigate(&canonical(&fx.url)).await.unwrap();
            // Self-filling pages (g07's feed chains fetch + timer while its sentinel is visible)
            // can outlast one settle when the host is loaded; the comparison needs the same
            // steady DOM the oracle saw, so observe until two consecutive candidate sets agree.
            let mut previous: Option<usize> = None;
            let mut rounds = 0;
            let (bundle, discovery) = loop {
                rounds += 1;
                ctx.settle(QuiescencePolicy::default()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(fx.settle_ms)).await;
                let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
                let discovery = CandidateDiscovery::discover_report(&bundle, &DiscoveryConfig::default());
                let n = discovery.candidates.len();
                if previous == Some(n) || rounds == 8 {
                    break (bundle, discovery);
                }
                previous = Some(n);
            };
            let keys = element_keys(&bundle, &discovery);
            eprintln!(
                "{}: crawlx {} candidates, {} unsupported surfaces",
                fx.id,
                keys.discovered.len(),
                keys.unsupported.len()
            );
            ours.insert(fx.id.clone(), keys);
            ctx.close().await.unwrap();
        }
        backend.close().await.expect("chromium must shut down");
        profiles.push((profile, ours));
    }
    let denials = proxy.denials();
    let dialed = proxy.dialed_hosts();
    proxy.shutdown().await;
    gym.shutdown().await;
    assert!(
        denials > 0,
        "G29 private-network probes must reach the checked proxy and be denied"
    );
    assert_eq!(
        dialed,
        vec![("127.0.0.1".to_owned(), origin_port)],
        "only the retained fixture listener may be dialed"
    );

    let standard = &profiles[0].1;
    let stealth = &profiles[1].1;
    for fx in &job.fixtures {
        assert_eq!(
            standard[&fx.id].discovered, stealth[&fx.id].discovered,
            "{}: Standard and Stealth discover different controls",
            fx.id
        );
        assert_eq!(
            standard[&fx.id].unsupported, stealth[&fx.id].unsupported,
            "{}: Standard and Stealth report different unsupported surfaces",
            fx.id
        );
    }
    // Console.enable is intentionally absent in Stealth. It is not an
    // actionability capability and is the only excluded telemetry-domain difference.
    for (profile, ours) in profiles {
        let cmp = compare_discovery(&ours, &report);
        let out = oracle_dir()
            .join("out")
            .join(format!("discovery-comparison.{}.{profile:?}.json", cmp.driver));
        std::fs::write(&out, serde_json::to_string_pretty(&cmp).unwrap()).unwrap();
        for f in &cmp.fixtures {
            eprintln!(
                "{}: oracle-actionable {}, discovered {}, unsupported {}, missed {}{}",
                f.id,
                f.oracle_actionable,
                f.discovered,
                f.unsupported,
                f.missed.len(),
                f.oracle_error
                    .as_ref()
                    .map_or(String::new(), |e| format!(" (oracle error: {e})"))
            );
            for k in &f.missed {
                eprintln!("    missed {k}");
            }
        }
        eprintln!(
        "{} {}: recall {:.4} over {} oracle-actionable elements ({} discovered); parity failures: {:?}; report {}",
        cmp.driver,
        cmp.driver_version,
        cmp.recall,
        cmp.oracle_actionable,
        cmp.discovered,
        cmp.parity_failures,
        out.display()
    );
        assert!(
            cmp.oracle_errors.is_empty(),
            "the oracle could not enumerate {:?}",
            cmp.oracle_errors
        );
        assert!(
            cmp.oracle_actionable >= MIN_ORACLE_ELEMENTS,
            "only {} oracle-actionable elements; the recall figure needs >= {MIN_ORACLE_ELEMENTS}",
            cmp.oracle_actionable
        );
        assert!(
            cmp.recall >= RECALL_FLOOR,
            "AX recall {:.4} < {RECALL_FLOOR} ({} of {})",
            cmp.recall,
            cmp.discovered,
            cmp.oracle_actionable
        );
        assert!(
            cmp.parity_failures.is_empty(),
            "capability parity failed on {:?} (see the `missed` lists above)",
            cmp.parity_failures
        );
        assert!(cmp.passes());
    }
}
