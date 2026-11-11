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

/// The eight second-click reveal pages (a first click creates, arms or swaps the control whose
/// click sends the request), each with a marker of the construct its page must keep.
const REVEAL_PAGES: [(&str, &str); 8] = [
    (
        "/javascript/interactive/multi-step-request-event-attribute.found",
        "setAttribute('onclick'",
    ),
    (
        "/javascript/interactive/multi-step-request-event-listener-div-dom.found",
        "createElement('div')",
    ),
    (
        "/javascript/interactive/multi-step-request-event-listener-div.found",
        "createElement('div')",
    ),
    (
        "/javascript/interactive/multi-step-request-event-listener-dom.found",
        "createElement('button')",
    ),
    (
        "/javascript/interactive/multi-step-request-event-listener.found",
        "createElement('button')",
    ),
    (
        "/javascript/interactive/multi-step-request-redefine-event-attribute.found",
        "this.setAttribute('onclick'",
    ),
    (
        "/javascript/interactive/multi-step-request-remove-button.found",
        "removeChild",
    ),
    (
        "/javascript/interactive/multi-step-request-remove-event-listener.found",
        "removeEventListener",
    ),
];

/// The hash-router page: the route change, not a link, loads the target.
const ROUTER_TARGET: &str = "/javascript/frameworks/polymer/polymer-router.found";

/// The destructive-click page: the safety kernel must deny the click, so nothing may ever
/// request this target with a mutating method.
const DESTRUCTIVE_TARGET: &str = "/javascript/interactive/js-delete.found";

/// The deferred targets and the word their recorded reason must carry: the exact set no plane
/// reaches today (every one needs a change in the extractor, not in the fixture).
const DEFERRED: [(&str, &str); 5] = [
    ("/html/body/img/src-data.found", "data:"),
    ("/html/head/profile.found", "profile"),
    ("/html/head/comment-conditional.found", "conditional comment"),
    ("/html/head/meta/content-pinned-websites.found", "bare"),
    ("/html/head/meta/content-reading-view.found", "bare"),
];

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
                deferred_reason: None,
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
    // the page table carries no reasons: compare everything else, then the reasons below
    let without_reasons: Vec<MazeTarget> = m
        .expected
        .crawl_maze
        .iter()
        .cloned()
        .map(|mut t| {
            t.deferred_reason = None;
            t
        })
        .collect();
    assert_eq!(without_reasons, table_targets());
    assert_eq!(m.expected.crawl_maze.len(), 91);
    let planes = |p: MazePlane| m.expected.crawl_maze.iter().filter(|t| t.plane == p).count();
    assert_eq!(planes(MazePlane::Static), 61);
    assert_eq!(planes(MazePlane::Browser), 25);
    assert_eq!(planes(MazePlane::Deferred), 5);
}

/// The deferred entries are exactly the recorded set, each with a precise reason, and the
/// page table agrees: promoting one (or deferring a new one) must touch this list.
#[test]
fn deferred_entries_are_exactly_the_recorded_set() {
    let m = FixtureManifest::embedded("g32").unwrap();
    let deferred: Vec<&MazeTarget> = m
        .expected
        .crawl_maze
        .iter()
        .filter(|t| t.plane == MazePlane::Deferred)
        .collect();
    let listed: BTreeSet<&str> = DEFERRED.iter().map(|(p, _)| *p).collect();
    let in_manifest: BTreeSet<&str> = deferred.iter().map(|t| t.path.as_str()).collect();
    assert_eq!(in_manifest, listed, "deferred set drifted from the recorded list");
    for (path, word) in DEFERRED {
        let t = deferred.iter().find(|t| t.path == path).unwrap();
        let reason = t.deferred_reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains(word),
            "{path}: reason {reason:?} must mention {word:?}"
        );
        assert!(reason.len() > 40, "{path}: reason too vague: {reason:?}");
        // the page table agrees: the page that references it is deferred too
        let page = crawl_maze::page_for(path).unwrap();
        assert_eq!(page.plane, MazePlane::Deferred, "{path}");
        assert_eq!(page.path, t.page, "{path}");
    }
    // a reason on a non-deferred entry is a manifest error
    assert!(m
        .expected
        .crawl_maze
        .iter()
        .filter(|t| t.plane != MazePlane::Deferred)
        .all(|t| t.deferred_reason.is_none()));
}

/// The eight second-click reveals, the hash router and the destructive click stay
/// browser-plane pages whose target is not a plain link: a crawler has to run the page
/// (click, route change) to be sure of reaching it.
#[test]
fn reveal_router_and_destructive_pages_stay_in_the_browser_plane() {
    let m = FixtureManifest::embedded("g32").unwrap();
    let mut cases: Vec<(&str, &str)> = REVEAL_PAGES.to_vec();
    cases.push((ROUTER_TARGET, "hashchange"));
    cases.push((DESTRUCTIVE_TARGET, "'DELETE'"));
    for (target, marker) in cases {
        let entry = m
            .expected
            .crawl_maze
            .iter()
            .find(|t| t.path == target)
            .unwrap_or_else(|| panic!("{target} left the manifest"));
        assert_eq!(entry.plane, MazePlane::Browser, "{target}");
        assert_eq!(entry.category, "javascript", "{target}");
        let page = crawl_maze::page_for(target).unwrap_or_else(|| panic!("{target} left the page table"));
        assert_eq!(page.plane, MazePlane::Browser, "{target}");
        assert_eq!(page.path, entry.page, "{target}");
        let body = page.render("127.0.0.1:41233").body;
        assert!(
            body.contains(marker),
            "{target}: page lost its {marker:?} construct"
        );
        assert!(
            body.contains("<button") || body.contains("<a href=\"#"),
            "{target}: no control on the page"
        );
        assert!(
            !body.contains(&format!("href=\"{TEST_PREFIX}{target}")),
            "{target}: linked directly"
        );
    }
    // second-click reveals: the second control is built by script, never in the served markup
    for (target, _) in REVEAL_PAGES {
        let body = crawl_maze::page_for(target)
            .unwrap()
            .render("127.0.0.1:41233")
            .body;
        assert!(
            !body.contains("id=\"secret\""),
            "{target}: the second control is in the initial markup"
        );
    }
}

/// Reveal and router targets a run did not request.
fn reveal_and_router_missing(s: &MazeScore) -> Vec<&'static str> {
    REVEAL_PAGES
        .iter()
        .map(|(t, _)| *t)
        .chain([ROUTER_TARGET])
        .filter(|t| s.missing.iter().any(|m| m == t))
        .collect()
}

/// No request of the run is a forbidden effect of `manifest` under `profile`, and nothing
/// ever sent a DELETE to the destructive page's endpoint.
fn assert_no_destructive_request(
    ledger: &crawlx_bench::gym::ledger::Ledger,
    manifest: &FixtureManifest,
    profile: SafetyProfile,
) {
    let ops = ledger.ops("g32");
    let violations: Vec<&(String, String)> = ops
        .iter()
        .filter(|(m, p)| {
            manifest
                .expected
                .forbidden_ops
                .iter()
                .any(|f| f.matches(m, p, profile))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "forbidden requests reached the gym: {violations:?}"
    );
    assert_eq!(
        ledger.count_ops("DELETE", &format!("{TEST_PREFIX}{DESTRUCTIVE_TARGET}")),
        0,
        "the destructive click was executed: {ops:?}"
    );
}

/// The destructive click is a forbidden effect under every profile that runs a browser:
/// the manifest names it, so scorers and the safety checks can call a DELETE a violation.
#[test]
fn destructive_click_is_a_forbidden_effect_for_safe_profiles() {
    let m = FixtureManifest::embedded("g32").unwrap();
    let path = format!("{TEST_PREFIX}{DESTRUCTIVE_TARGET}");
    assert_eq!(
        m.expected.forbidden_ops.len(),
        1,
        "{:?}",
        m.expected.forbidden_ops
    );
    let forbidden = |method: &str, p: &str, profile| {
        m.expected
            .forbidden_ops
            .iter()
            .any(|f| f.matches(method, p, profile))
    };
    for profile in [SafetyProfile::ReadOnly, SafetyProfile::TestEnvironment] {
        assert!(forbidden("DELETE", &path, profile), "{profile:?}");
        assert!(forbidden("delete", &path, profile), "{profile:?}");
        assert!(!forbidden("GET", &path, profile), "{profile:?}");
        let put = format!("{TEST_PREFIX}/javascript/interactive/js-put.found");
        assert!(!forbidden("PUT", &put, profile), "{profile:?}");
    }
}

/// `bench/baselines/crawl-maze.json` carries the manifest's target counts and keeps the
/// reveal, router and deferred rows where the manifest puts them.
#[test]
fn baseline_counts_match_the_manifest() {
    let m = FixtureManifest::embedded("g32").unwrap();
    let all: BTreeSet<&str> = m.expected.crawl_maze.iter().map(|t| t.path.as_str()).collect();
    let plane_count = |p: MazePlane| m.expected.crawl_maze.iter().filter(|t| t.plane == p).count();
    let b = load_baseline();
    let mut runs = vec![("static", &b.static_plane)];
    if let Some(h) = &b.hybrid {
        runs.push(("hybrid", h));
    }
    for (name, s) in runs {
        assert_eq!(s.expected as usize, all.len(), "{name}: target count");
        for plane in [MazePlane::Static, MazePlane::Browser, MazePlane::Deferred] {
            assert_eq!(
                s.per_plane[&plane].expected as usize,
                plane_count(plane),
                "{name}: {plane:?}"
            );
        }
        for cat in ["css", "headers", "html", "javascript", "misc"] {
            let want = m.expected.crawl_maze.iter().filter(|t| t.category == cat).count();
            assert_eq!(s.per_category[cat].expected as usize, want, "{name}: {cat}");
        }
        let found: BTreeSet<&str> = s.found.iter().map(String::as_str).collect();
        let missing: BTreeSet<&str> = s.missing.iter().map(String::as_str).collect();
        assert!(found.is_disjoint(&missing), "{name}: found and missing overlap");
        assert_eq!(
            found.union(&missing).copied().collect::<BTreeSet<_>>(),
            all,
            "{name}: rows differ from the manifest"
        );
        assert_eq!(s.total as usize, found.len(), "{name}");
        for (target, _) in REVEAL_PAGES {
            assert!(
                found.contains(target),
                "{name}: {target} no longer recorded as found"
            );
        }
        assert!(
            found.contains(ROUTER_TARGET),
            "{name}: router target no longer recorded as found"
        );
        assert!(
            !found.contains(DESTRUCTIVE_TARGET),
            "{name}: the destructive target was recorded as requested"
        );
        for (target, _) in DEFERRED {
            assert!(
                !found.contains(target),
                "{name}: deferred {target} recorded as found, promote it"
            );
        }
    }
    assert_eq!(
        b.static_plane.per_plane[&MazePlane::Static].found,
        b.static_plane.per_plane[&MazePlane::Static].expected,
        "static plane floor"
    );
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
    // second-click reveals and the hash router are mined from their scripts; the destructive
    // click is never executed by a static run
    let reveal_missing = reveal_and_router_missing(&s);
    assert!(
        reveal_missing.is_empty(),
        "reveal/router targets lost: {reveal_missing:?}"
    );
    assert_no_destructive_request(&ledger, &manifest, SafetyProfile::ReadOnly);

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
    // every second-click reveal and the hash router are reached; the destructive click is
    // denied by the safety kernel, so the gym never sees a DELETE
    let reveal_missing = reveal_and_router_missing(&s);
    assert!(
        reveal_missing.is_empty(),
        "hybrid lost reveal/router targets: {reveal_missing:?}"
    );
    assert_no_destructive_request(&gym.ledger(), &manifest, SafetyProfile::TestEnvironment);
    assert!(
        report.counters.interactions.policy_blocked > 0,
        "the kernel denied no click: {:?}",
        report.counters.interactions
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
