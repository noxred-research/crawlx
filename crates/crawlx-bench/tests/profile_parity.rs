//! Stealth-versus-standard launch-profile parity and the stealth admission mapping.
//!
//! * `browser_stealth_discovers_the_same_candidates_as_standard_on_g01_to_g30` runs every catalog
//!   page G01–G30 through crawlx on a Standard and on a Stealth Chromium and requires the
//!   discovered-candidate and unsupported-surface key sets to agree within
//!   [`PARITY_TOLERANCE`] (1 percentage point). It needs no reference driver (the
//!   reference-driver differential in `oracle_differential.rs` skips without `node`), only a
//!   Chromium; skipped without one.
//! * The `compare.mjs` tests run the reference-driver comparator on authored result files
//!   (skipped without `node`): it refuses results of different drivers or driver builds, and
//!   it blocks (exit status 2) on a false-actionable control but not on a driver gap.
//! * The HTTP test posts a crawl with the stealth launch profile under the `read_only` safety
//!   profile to an in-process API and expects the `422` admission rejection `profile_conflict`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_api::auth::generate_key;
use crawlx_api::{run_until, ApiConfig, ApiKeyBootstrap};
use crawlx_bench::gym::fixtures::CATALOG_ROWS;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::oracle::discovery::{
    discovery_job, element_keys, CrawlxElements, DiscoveryFixture, MIN_ORACLE_ELEMENTS,
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
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Largest share of discovered keys (percentage points / 100) the two launch profiles may
/// disagree on.
const PARITY_TOLERANCE: f64 = 0.01;

/// Catalog rows compared: every G01–G30 entry page (G29 is the zero-control egress page).
const ROWS: std::ops::RangeInclusive<u32> = 1..=30;

/// Share of `a` and `b` that both contain: `|a ∩ b| / |a ∪ b|`, `1.0` for two empty sets.
fn agreement(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    let union = a.union(b).count();
    if union == 0 {
        return 1.0;
    }
    a.intersection(b).count() as f64 / union as f64
}

/// Agreement over the union of every fixture's keys, each key namespaced by its fixture.
fn aggregate_agreement(
    a: &BTreeMap<String, BTreeSet<String>>,
    b: &BTreeMap<String, BTreeSet<String>>,
) -> (f64, usize) {
    let namespaced = |m: &BTreeMap<String, BTreeSet<String>>| -> BTreeSet<String> {
        m.iter()
            .flat_map(|(fixture, keys)| keys.iter().map(move |k| format!("{fixture}\u{0}{k}")))
            .collect()
    };
    let (a, b) = (namespaced(a), namespaced(b));
    (agreement(&a, &b), a.union(&b).count())
}

#[test]
fn agreement_is_exact_for_equal_sets_and_drops_with_every_divergent_key() {
    let set = |keys: &[&str]| -> BTreeSet<String> { keys.iter().map(|k| (*k).to_owned()).collect() };
    assert!((agreement(&set(&[]), &set(&[])) - 1.0).abs() < f64::EPSILON);
    assert!((agreement(&set(&["a", "b"]), &set(&["a", "b"])) - 1.0).abs() < f64::EPSILON);
    assert!((agreement(&set(&["a", "b"]), &set(&["a", "c"])) - 1.0 / 3.0).abs() < 1e-12);

    // one divergent key in 100 is 99 % agreement (within the tolerance); two are not
    let hundred: BTreeMap<String, BTreeSet<String>> =
        BTreeMap::from([("g01".to_owned(), (0..100).map(|i| format!("k{i}")).collect())]);
    let mut one_missing = hundred.clone();
    one_missing.get_mut("g01").unwrap().remove("k0");
    let (share, keys) = aggregate_agreement(&hundred, &one_missing);
    assert_eq!(keys, 100);
    assert!(share >= 1.0 - PARITY_TOLERANCE - 1e-12, "{share}");
    let mut two_missing = one_missing.clone();
    two_missing.get_mut("g01").unwrap().remove("k1");
    let (share, _) = aggregate_agreement(&hundred, &two_missing);
    assert!(share < 1.0 - PARITY_TOLERANCE, "{share}");

    // the same key under two fixtures is two keys
    let a = BTreeMap::from([("g01".to_owned(), set(&["x"])), ("g02".to_owned(), set(&["x"]))]);
    let b = BTreeMap::from([("g01".to_owned(), set(&["x"]))]);
    assert_eq!(aggregate_agreement(&a, &b).1, 2);
}

fn canonical(url: &str) -> crawlx_core::url::CanonicalUrl {
    Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

fn catalog_fixtures() -> Vec<FixtureManifest> {
    CATALOG_ROWS
        .iter()
        .filter(|(row, _)| {
            let n: u32 = row.trim_start_matches('G').parse().unwrap();
            ROWS.contains(&n)
        })
        .map(|(_, id)| FixtureManifest::embedded(id).unwrap())
        .collect()
}

/// Extra observations of a fixture whose two profiles disagree. A page that builds its frames
/// by script (g05's nested `srcdoc` frames) can outlast the settle on a loaded host in one
/// profile only; a real divergence shows again on every observation. Each profile's keys are
/// the union over its observations, so a transient miss heals and a persistent one does not.
const RECHECKS: usize = 2;

async fn launch(exe: &std::path::Path, profile: LaunchProfile, proxy_port: u16) -> ChromiumBackend {
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe.to_path_buf();
    cfg.launch_profile = profile;
    cfg.allow_unpinned = true;
    cfg.egress_proxy_port = Some(proxy_port);
    match ChromiumBackend::launch(cfg.clone()).await {
        Ok(b) => b,
        Err(first) => {
            eprintln!(
                "warning: launch failed ({first}); retrying once with --no-sandbox (CI containers only)"
            );
            cfg.unsafe_no_sandbox_for_ci = true;
            ChromiumBackend::launch(cfg).await.expect("chromium must launch")
        }
    }
}

/// crawlx's observation of one fixture page under `profile`: the same settle and the default
/// discovery ladder as the reference-driver differential.
async fn observe_keys(
    backend: &ChromiumBackend,
    profile: LaunchProfile,
    proxy_port: u16,
    fx: &DiscoveryFixture,
) -> CrawlxElements {
    let mut context = ContextConfig::new(SessionId::new());
    context.launch_profile = profile;
    context.egress_proxy_port = Some(proxy_port);
    let mut ctx = backend.new_context(context).await.unwrap();
    ctx.navigate(&canonical(&fx.url)).await.unwrap();
    // Observe until two consecutive observations name the same candidates: self-filling
    // pages (g07) can outlast one settle on a loaded host.
    let mut previous: Option<BTreeSet<String>> = None;
    let mut rounds = 0;
    let keys = loop {
        rounds += 1;
        ctx.settle(QuiescencePolicy::default()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(fx.settle_ms)).await;
        let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
        let discovery = CandidateDiscovery::discover_report(&bundle, &DiscoveryConfig::default());
        let keys = element_keys(&bundle, &discovery);
        if previous.as_ref() == Some(&keys.discovered) || rounds == 8 {
            break keys;
        }
        previous = Some(keys.discovered.clone());
    };
    ctx.close().await.unwrap();
    keys
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_stealth_discovers_the_same_candidates_as_standard_on_g01_to_g30() {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
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
    let job = discovery_job(&catalog_fixtures(), origin.as_str().trim_end_matches('/'));
    assert_eq!(job.fixtures.len(), 30, "G01-G30 are all in the catalog");

    // Both launch profiles run at once and see each fixture back to back, so a loaded
    // host slows them alike.
    let standard_backend = launch(&exe, LaunchProfile::Standard, proxy_port).await;
    let stealth_backend = launch(&exe, LaunchProfile::Stealth, proxy_port).await;
    let mut standard: BTreeMap<String, CrawlxElements> = BTreeMap::new();
    let mut stealth: BTreeMap<String, CrawlxElements> = BTreeMap::new();
    for fx in &job.fixtures {
        let mut s = observe_keys(&standard_backend, LaunchProfile::Standard, proxy_port, fx).await;
        let mut t = observe_keys(&stealth_backend, LaunchProfile::Stealth, proxy_port, fx).await;
        for recheck in 1..=RECHECKS {
            if s == t {
                break;
            }
            eprintln!(
                "{}: profiles disagree, observation {} of {}",
                fx.id,
                recheck + 1,
                RECHECKS + 1
            );
            let (again_s, again_t) = (
                observe_keys(&standard_backend, LaunchProfile::Standard, proxy_port, fx).await,
                observe_keys(&stealth_backend, LaunchProfile::Stealth, proxy_port, fx).await,
            );
            s.discovered.extend(again_s.discovered);
            s.unsupported.extend(again_s.unsupported);
            t.discovered.extend(again_t.discovered);
            t.unsupported.extend(again_t.unsupported);
        }
        standard.insert(fx.id.clone(), s);
        stealth.insert(fx.id.clone(), t);
    }
    standard_backend.close().await.expect("chromium must shut down");
    stealth_backend.close().await.expect("chromium must shut down");
    proxy.shutdown().await;
    gym.shutdown().await;

    let discovered = |m: &BTreeMap<String, CrawlxElements>| -> BTreeMap<String, BTreeSet<String>> {
        m.iter()
            .map(|(id, e)| (id.clone(), e.discovered.clone()))
            .collect()
    };
    let unsupported = |m: &BTreeMap<String, CrawlxElements>| -> BTreeMap<String, BTreeSet<String>> {
        m.iter()
            .map(|(id, e)| (id.clone(), e.unsupported.clone()))
            .collect()
    };
    let (found, found_total) = aggregate_agreement(&discovered(&standard), &discovered(&stealth));
    let (surfaces, _) = aggregate_agreement(&unsupported(&standard), &unsupported(&stealth));
    for fx in &job.fixtures {
        let (s, t) = (&standard[&fx.id], &stealth[&fx.id]);
        eprintln!(
            "{}: standard {} / stealth {} candidates, agreement {:.4}",
            fx.id,
            s.discovered.len(),
            t.discovered.len(),
            agreement(&s.discovered, &t.discovered)
        );
        for key in s.discovered.symmetric_difference(&t.discovered) {
            eprintln!("    differs: {key}");
        }
    }
    eprintln!("standard-vs-stealth agreement: candidates {found:.4} over {found_total} keys, unsupported {surfaces:.4}");
    assert!(
        found_total >= MIN_ORACLE_ELEMENTS,
        "only {found_total} candidate keys; the parity figure needs >= {MIN_ORACLE_ELEMENTS}"
    );
    assert!(
        found >= 1.0 - PARITY_TOLERANCE,
        "Standard and Stealth candidate sets agree on {found:.4} < {:.2}",
        1.0 - PARITY_TOLERANCE
    );
    assert!(
        surfaces >= 1.0 - PARITY_TOLERANCE,
        "Standard and Stealth unsupported-surface sets agree on {surfaces:.4} < {:.2}",
        1.0 - PARITY_TOLERANCE
    );
    // a fixture is never entirely missing on one side
    for fx in &job.fixtures {
        assert_eq!(
            standard[&fx.id].discovered.is_empty(),
            stealth[&fx.id].discovered.is_empty(),
            "{}: one profile found no candidates",
            fx.id
        );
    }
}

// ---- comparator (bench/browser-oracle/compare.mjs) ------------------------------------------

fn compare_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../bench/browser-oracle/compare.mjs")
        .canonicalize()
        .expect("bench/browser-oracle/compare.mjs exists")
}

fn node_available() -> bool {
    let ok = std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("SKIP: no `node` on PATH");
    }
    ok
}

fn oracle_file(
    dir: &std::path::Path,
    name: &str,
    driver: &str,
    version: &str,
    results: &[(&str, &str)],
) -> PathBuf {
    let results: Vec<Value> = results
        .iter()
        .map(|(id, verdict)| json!({"id": id, "selector": format!("#{id}"), "verdict": verdict, "reason": "obscured"}))
        .collect();
    let path = dir.join(name);
    std::fs::write(
        &path,
        serde_json::to_string(&json!({
            "driver": driver,
            "driver_version": version,
            "results": results,
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

fn crawlx_file(dir: &std::path::Path, verdicts: &[(&str, &str)]) -> PathBuf {
    let map: serde_json::Map<String, Value> = verdicts
        .iter()
        .map(|(k, v)| ((*k).to_owned(), json!(v)))
        .collect();
    let path = dir.join("crawlx.json");
    std::fs::write(&path, serde_json::to_string(&json!({ "verdicts": map })).unwrap()).unwrap();
    path
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_compare(oracles: &[&PathBuf], crawlx: &PathBuf) -> Ran {
    let mut cmd = std::process::Command::new("node");
    cmd.arg(compare_script());
    for o in oracles {
        cmd.arg("--oracle").arg(o);
    }
    cmd.arg("--crawlx").arg(crawlx);
    let out = cmd.output().unwrap();
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[test]
fn comparator_refuses_to_merge_results_from_different_drivers() {
    if !node_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let reference = oracle_file(
        dir.path(),
        "reference.json",
        "reference",
        "1.64.1",
        &[("a", "actionable")],
    );
    let hardened = oracle_file(
        dir.path(),
        "hardened.json",
        "hardened",
        "1.64.2",
        &[("b", "actionable")],
    );
    let crawlx = crawlx_file(dir.path(), &[("a", "actionable"), ("b", "actionable")]);
    let ran = run_compare(&[&reference, &hardened], &crawlx);
    assert_ne!(
        ran.code,
        Some(0),
        "mixed drivers must not compare: {}",
        ran.stdout
    );
    assert!(
        ran.stderr
            .contains("refusing to merge results from different drivers: reference@1.64.1, hardened@1.64.2")
            || ran.stderr.contains(
                "refusing to merge results from different drivers: hardened@1.64.2, reference@1.64.1"
            ),
        "{}",
        ran.stderr
    );
    assert!(
        ran.stdout.is_empty(),
        "no verdict is printed for a refused merge: {}",
        ran.stdout
    );
}

#[test]
fn comparator_refuses_to_merge_two_builds_of_the_same_driver() {
    if !node_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let old = oracle_file(
        dir.path(),
        "old.json",
        "reference",
        "1.64.0",
        &[("a", "actionable")],
    );
    let new = oracle_file(
        dir.path(),
        "new.json",
        "reference",
        "1.64.1",
        &[("b", "actionable")],
    );
    let crawlx = crawlx_file(dir.path(), &[("a", "actionable")]);
    let ran = run_compare(&[&old, &new], &crawlx);
    assert_ne!(ran.code, Some(0));
    assert!(
        ran.stderr
            .contains("refusing to merge results from different drivers"),
        "{}",
        ran.stderr
    );
}

#[test]
fn comparator_blocks_on_a_false_actionable_control_and_only_on_that() {
    if !node_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let oracle = oracle_file(
        dir.path(),
        "reference.json",
        "reference",
        "1.64.1",
        &[
            ("covered", "not_actionable"),
            ("gap", "oracle_gap"),
            ("fine", "actionable"),
        ],
    );
    // crawlx calls an obscured control actionable: blocking, exit status 2
    let wrong = crawlx_file(
        dir.path(),
        &[
            ("covered", "actionable"),
            ("gap", "actionable"),
            ("fine", "actionable"),
        ],
    );
    let ran = run_compare(&[&oracle], &wrong);
    assert_eq!(ran.code, Some(2), "{} {}", ran.stdout, ran.stderr);
    let v: Value = serde_json::from_str(&ran.stdout).unwrap();
    assert_eq!(v["blocking"], true);
    assert_eq!(v["driver"], "reference");
    assert_eq!(v["false_actionable"].as_array().unwrap().len(), 1);
    assert_eq!(v["false_actionable"][0]["id"], "covered");
    assert_eq!(
        v["oracle_gaps"],
        json!(["gap"]),
        "a driver gap is reported, never a failure"
    );

    // the control crawlx refuses while the driver acts is non-blocking and counted as a rate
    let strict = crawlx_file(
        dir.path(),
        &[
            ("covered", "not_actionable"),
            ("gap", "actionable"),
            ("fine", "not_actionable"),
        ],
    );
    let ran = run_compare(&[&oracle], &strict);
    assert_eq!(ran.code, Some(0), "{} {}", ran.stdout, ran.stderr);
    let v: Value = serde_json::from_str(&ran.stdout).unwrap();
    assert_eq!(v["blocking"], false);
    assert_eq!(v["false_non_actionable"][0]["id"], "fine");
    assert!((v["false_non_actionable_rate"].as_f64().unwrap() - 1.0 / 3.0).abs() < 1e-9);
}

// ---- HTTP mapping of the stealth admission gate ---------------------------------------------

struct Api {
    base: String,
    key: String,
    stop: CancellationToken,
    server: tokio::task::JoinHandle<Result<(), crawlx_api::ApiError>>,
    _dir: tempfile::TempDir,
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
async fn start_api() -> Api {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let key = generate_key();
    let cfg = ApiConfig {
        bind: ([127, 0, 0, 1], port).into(),
        database_url: None,
        artifacts_dir: dir.path().to_path_buf(),
        api_keys: vec![ApiKeyBootstrap::new("acme", &key)],
        rate_limit_per_minute: 0,
        webhook_secret: "whsec_x".to_owned(),
        metrics_bind: None,
        ..ApiConfig::default()
    };
    let stop = CancellationToken::new();
    let server = tokio::spawn(run_until(cfg, stop.clone()));
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let mut up = false;
    for _ in 0..100 {
        if client.get(format!("{base}/v1/openapi.json")).send().await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "server did not come up");
    Api {
        base,
        key,
        stop,
        server,
        _dir: dir,
    }
}

impl Api {
    #[allow(
        clippy::disallowed_types,
        reason = "owned loopback fixture transport boundary"
    )]
    async fn post_crawl(&self, body: &Value) -> (reqwest::StatusCode, Value) {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/crawls", self.base))
            .bearer_auth(&self.key)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap())
    }

    async fn shutdown(self) {
        self.stop.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), self.server).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealth_launch_profile_under_read_only_is_http_422_profile_conflict() {
    let api = start_api().await;
    let (status, body) = api
        .post_crawl(&json!({
            "seedUrl": "https://app.example.test/",
            "mode": "dynamic",
            "safety": {"profile": "read_only"},
            "dynamic": {"launchProfile": "stealth"},
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let details: Vec<(&str, &str)> = body["error"]["details"]
        .as_array()
        .unwrap_or_else(|| panic!("no error details in {body}"))
        .iter()
        .map(|d| (d["path"].as_str().unwrap(), d["code"].as_str().unwrap()))
        .collect();
    assert_eq!(
        details,
        [("/dynamic/launchProfile", "profile_conflict")],
        "exactly the stealth gate fires: {body}"
    );

    // the default launch profile under the same safety profile is admitted: the 422 above
    // is the stealth gate, not the request shape
    let (status, body) = api
        .post_crawl(&json!({
            "seedUrl": "https://app.example.test/",
            "mode": "dynamic",
            "safety": {"profile": "read_only"},
            "dynamic": {"launchProfile": "standard"},
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::ACCEPTED, "{body}");
    api.shutdown().await;
}
