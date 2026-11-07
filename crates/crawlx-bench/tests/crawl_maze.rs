//! G32 security-crawl-maze: the fixture's truth matches its page
//! table, the endpoint extractor finds every static-plane target from its page, the worker's
//! static plane reaches the static floor recorded in `bench/baselines/crawl-maze.json`, and
//! (with Chromium) the hybrid run adds browser-plane targets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::crawl_maze::{score_ledger, MazeScore};
use crawlx_bench::gym::fixtures::crawl_maze::{self, MazePage, PAGES, TEST_PREFIX};
use crawlx_bench::gym::manifest::{FixtureManifest, MazePlane, MazeTarget};
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, KnownFile, SafetyProfile};
use crawlx_extract::endpoints::{discover, DiscoveryInput};
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, LocalRun, Stores};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

/// Categories whose static-plane targets the release gate requires.
const STATIC_FLOOR: [&str; 4] = ["css", "headers", "html", "misc"];

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/baselines/crawl-maze.json")
}

/// `bench/baselines/crawl-maze.json`.
#[derive(Serialize, Deserialize, Debug)]
struct Baseline {
    version: u32,
    fixture: String,
    recorded: String,
    source: String,
    request: serde_json::Value,
    #[serde(rename = "static")]
    static_plane: MazeScore,
    hybrid: Option<MazeScore>,
}

fn load_baseline() -> Baseline {
    let text = std::fs::read_to_string(baseline_path()).expect("bench/baselines/crawl-maze.json");
    serde_json::from_str(&text).unwrap()
}

fn record_baselines() -> bool {
    std::env::var_os("CRAWLX_RECORD_BASELINES").is_some()
}

fn save_baseline(b: &Baseline) {
    let text = serde_json::to_string_pretty(b).unwrap();
    std::fs::write(baseline_path(), text + "\n").unwrap();
}

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

fn have_chromium() -> bool {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return false;
    }
    true
}

fn table_targets() -> Vec<MazeTarget> {
    PAGES
        .iter()
        .flat_map(|p| {
            p.targets.iter().map(move |t| MazeTarget {
                path: (*t).to_owned(),
                category: p.category().to_owned(),
                plane: p.plane,
                page: p.path.to_owned(),
            })
        })
        .collect()
}

/// The request the baseline was recorded with: static plane, loopback authorized, robots
/// `Allow:` paths and the sitemap seeded, the default extension filter off so the `.pdf`
/// target is fetched, JS-mined endpoints admitted (the default).
fn maze_request(manifest: &FixtureManifest, base_url: &str) -> crawlx_core::config::CreateCrawl {
    let mut req = crawl_request(manifest, base_url, 32, SafetyProfile::ReadOnly).unwrap();
    req.mode = CrawlMode::Static;
    req.dynamic.enabled = false;
    req.scope.known_files = vec![KnownFile::RobotsPaths, KnownFile::Sitemap];
    req.scope.no_default_extension_filter = true;
    req.limits.urls = 2_000;
    req.limits.duration_seconds = 120;
    req
}

// ---- truth ----------------------------------------------------------------------------------

#[test]
fn manifest_lists_exactly_the_page_table() {
    let m = FixtureManifest::embedded("g32").unwrap();
    assert_eq!(m.expected.crawl_maze, table_targets());
    assert_eq!(m.expected.crawl_maze.len(), 91);
    let planes = |p: MazePlane| m.expected.crawl_maze.iter().filter(|t| t.plane == p).count();
    assert_eq!(planes(MazePlane::Static), 61);
    assert_eq!(planes(MazePlane::Browser), 25);
    assert_eq!(planes(MazePlane::Deferred), 5);
}

fn discovered_get_paths(p: &MazePage, host: &str) -> BTreeSet<String> {
    let r = p.render(host);
    let url = url::Url::parse(&format!("http://{host}/g32/{}", p.path)).unwrap();
    let mut headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    headers.push(("content-type".to_owned(), r.content_type.to_owned()));
    let input = DiscoveryInput {
        url: &url,
        status: r.status,
        headers: &headers,
        content_type: Some(r.content_type),
        body: r.body.as_bytes(),
        depth: 1,
    };
    discover(&input)
        .expect("maze fixture endpoint discovery must succeed")
        .into_iter()
        .filter(|e| e.method.as_str() == "GET")
        .map(|e| e.url.path().to_owned())
        .collect()
}

/// Every static-plane target is produced by the extractor from its own page (or named by
/// the fixture's robots/sitemap for the known-files cases); every deferred target is not,
/// which is what makes it deferred.
#[test]
fn extractor_finds_every_static_target_from_its_page() {
    let host = "127.0.0.1:41233";
    let robots = crawl_maze::robots_txt(host);
    let sitemap = crawl_maze::serve("sitemap.xml", host).unwrap().body;
    let mut missing = Vec::new();
    let mut unexpectedly_found = Vec::new();
    for p in PAGES.iter().filter(|p| !p.targets.is_empty()) {
        let got = discovered_get_paths(p, host);
        for t in p.targets {
            let want = format!("{TEST_PREFIX}{t}");
            let known_file = p.path.starts_with("misc/known-files/");
            let found =
                got.contains(&want) || (known_file && (robots.contains(&want) || sitemap.contains(&want)));
            match p.plane {
                MazePlane::Static if !found => missing.push(format!("{} -> {t}: {got:?}", p.path)),
                MazePlane::Deferred if found => unexpectedly_found.push(format!("{} -> {t}", p.path)),
                _ => {}
            }
        }
    }
    assert!(
        missing.is_empty(),
        "static targets the extractor misses:\n{}",
        missing.join("\n")
    );
    assert!(
        unexpectedly_found.is_empty(),
        "deferred targets the extractor now finds (promote them to static):\n{}",
        unexpectedly_found.join("\n")
    );
}

// ---- worker runs ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_plane_reaches_the_crawl_maze_floor() {
    let gym = gym().await;
    gym.claim_origin("g32");
    let manifest = FixtureManifest::embedded("g32").unwrap();
    let req = maze_request(&manifest, &gym.base_url);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(req.clone(), cfg).with_stores(stores),
    ))
    .await
    .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    let ledger = gym.ledger();
    let targets = &manifest.expected.crawl_maze;
    let s = score_ledger(&ledger, "g32", targets, TEST_PREFIX);
    eprintln!("{}", s.render_markdown());

    // the release floor: every static-plane target of css, headers, html and misc
    let floor_missing = s.missing_in(targets, MazePlane::Static, &STATIC_FLOOR);
    assert!(
        floor_missing.is_empty(),
        "static floor not reached: {floor_missing:?}"
    );
    // known files were really read, not guessed
    let ops = ledger.ops("_gym");
    assert!(ops.iter().any(|(_, p)| p == "/robots.txt"), "{ops:?}");
    assert!(ledger.ops("g32").iter().any(|(_, p)| p == "/g32/sitemap.xml"));

    let mut baseline = load_baseline();
    if record_baselines() {
        baseline.recorded = chrono::Utc::now().format("%Y-%m-%d").to_string();
        baseline.request["static"] = serde_json::json!({
            "mode": "static",
            "seedUrl": "/g32/",
            "scope": { "knownFiles": ["robots_paths", "sitemap"], "noDefaultExtensionFilter": true, "jsEndpoints": true },
            "safety": { "profile": "read_only", "respectRobotsTxt": true }
        });
        baseline.static_plane = s.clone();
        save_baseline(&baseline);
    }
    // no regression against the committed numbers: the static plane is deterministic
    let recorded: BTreeSet<&str> = baseline.static_plane.found.iter().map(String::as_str).collect();
    let now: BTreeSet<&str> = s.found.iter().map(String::as_str).collect();
    let lost: Vec<&&str> = recorded.difference(&now).collect();
    assert!(
        lost.is_empty(),
        "targets found in the baseline but not now: {lost:?}"
    );
    assert_eq!(
        s.per_category["javascript"].found, baseline.static_plane.per_category["javascript"].found,
        "javascript category drifted from the baseline (re-record with CRAWLX_RECORD_BASELINES=1)"
    );
    gym.shutdown().await;
}

/// Hybrid run with Chromium over the `javascript` category (every browser-plane target plus
/// the two script-mined ones) and its `.found` endpoints: every JS page is rendered and
/// explored (`dynamic.alwaysBrowserPaths`), page hooks feed `fetch`/`pushState` URLs back.
/// The static categories are already covered by the static run; keeping the browser run to
/// one category bounds its wall clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_plane_adds_browser_targets() {
    if !have_chromium() {
        return;
    }
    let gym = gym().await;
    gym.claim_origin("g32");
    let manifest = FixtureManifest::embedded("g32").unwrap();
    let mut req = maze_request(&manifest, &gym.base_url);
    req.seed_url = url::Url::parse(&format!("{}/g32/javascript/", gym.base_url)).unwrap();
    req.mode = CrawlMode::Hybrid;
    req.dynamic.enabled = true;
    req.dynamic.page_hooks = true;
    req.dynamic.always_browser_paths = vec!["^/g32/javascript/".to_owned()];
    req.scope.crawl_entire_domain = true;
    req.scope.include_paths = vec!["^/g32/(javascript|test)/".to_owned()];
    req.safety.profile = SafetyProfile::TestEnvironment;
    req.limits.interactions = 400;
    req.limits.duration_seconds = 300;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(authorize_fixture(LocalRun::new(req, cfg).with_stores(stores)))
        .await
        .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    eprintln!(
        "hybrid run: status {:?}, {} pages, interactions {:?}",
        report.status,
        report.pages.len(),
        report.counters.interactions
    );
    let targets = &manifest.expected.crawl_maze;
    let s = score_ledger(&gym.ledger(), "g32", targets, TEST_PREFIX);
    eprintln!("{}", s.render_markdown());

    let mut baseline = load_baseline();
    // the script-mined javascript targets are still found through the URL plane
    let js_static = s.missing_in(targets, MazePlane::Static, &["javascript"]);
    assert!(
        js_static.is_empty(),
        "hybrid lost static javascript targets: {js_static:?}"
    );
    assert!(
        s.per_plane[&MazePlane::Browser].found > 0,
        "no browser-plane target reached: {:?}",
        s.missing
    );
    if let Some(recorded) = &baseline.hybrid {
        // the browser run is wall-clock bounded, so only a gross regression (less than half
        // of the recorded browser-plane count, e.g. page hooks or clicks broken) fails here
        let was = recorded.per_plane[&MazePlane::Browser].found;
        let now = s.per_plane[&MazePlane::Browser].found;
        assert!(
            now * 2 >= was,
            "browser-plane targets regressed from {was} to {now}: missing {:?}",
            s.missing
        );
    }
    if record_baselines() {
        baseline.request["hybrid"] = serde_json::json!({
            "mode": "hybrid",
            "seedUrl": "/g32/javascript/",
            "scope": { "crawlEntireDomain": true, "includePaths": ["^/g32/(javascript|test)/"], "knownFiles": ["robots_paths", "sitemap"], "noDefaultExtensionFilter": true },
            "dynamic": { "pageHooks": true, "alwaysBrowserPaths": ["^/g32/javascript/"] },
            "safety": { "profile": "test_environment" },
            "limits": { "interactions": 400, "durationSeconds": 300 },
            "note": "browser run scoped to the javascript category and its .found endpoints; wall-clock bounded"
        });
        baseline.hybrid = Some(s);
        save_baseline(&baseline);
    }
    gym.shutdown().await;
}
