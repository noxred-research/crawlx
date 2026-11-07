//! Worker-driven fixture scorecard gates and the `hybrid-mix` coverage ordering.
//!
//! Every row runs its fixture through the worker (`run_fixture`), scores the run with the
//! gym ledger as ground truth (`Scorecard::compute`) and asserts that every manifest
//! threshold passes and that the trail is clean. Dynamic rows skip without
//! Chromium; static rows (URL plane only) always run.

use super::common::*;
use crawlx_bench::gym::manifest::{FixtureManifest, Mechanism};
use crawlx_bench::gym::GymHandle;
use crawlx_bench::scorecard::{DiscoveredTarget, RunRows, Scorecard};
use crawlx_bench::trail::{verify_trail, TrailStore};
use crawlx_bench::worker_exec::rows_from_report;
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_elements::IdentityBuilder;
use crawlx_url::CanonicalizeOptions;
use crawlx_worker::RunReport;
use std::collections::{BTreeMap, BTreeSet};

/// Plane a row runs on. `Static` only where the manifest's checks are URL-plane facts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Static,
    Dynamic,
}

/// One gate row: the fixture, its plane, the crawl seed and the budgets the run gets.
struct Row {
    id: &'static str,
    mode: Mode,
    seed: u64,
    /// `limits.interactions`.
    interactions: u32,
    /// `limits.duration_seconds` (`crawl_request` defaults to 20 s; rows with more controls
    /// than one browser session clicks in 20 s get more wall clock).
    seconds: u32,
}

const fn row(id: &'static str, mode: Mode, seed: u64, interactions: u32, seconds: u32) -> Row {
    Row {
        id,
        mode,
        seed,
        interactions,
        seconds,
    }
}

/// Fixture scorecard rows. `Static` only where the manifest's checks are URL-plane facts (`s1`).
const ROWS: &[Row] = &[
    row("a2", Mode::Dynamic, 1302, 40, 30),
    row("async-late", Mode::Dynamic, 1303, 20, 20),
    row("div-buttons", Mode::Dynamic, 1304, 60, 60),
    row("g02", Mode::Dynamic, 1305, 150, 120),
    row("g03", Mode::Dynamic, 1306, 40, 40),
    row("g04", Mode::Dynamic, 1307, 60, 60),
    row("g05", Mode::Dynamic, 1308, 80, 90),
    row("g06", Mode::Dynamic, 1309, 60, 60),
    row("g07", Mode::Dynamic, 1310, 80, 90),
    row("g08", Mode::Dynamic, 1311, 30, 30),
    row("g12", Mode::Dynamic, 1312, 40, 40),
    row("g13", Mode::Dynamic, 1313, 60, 60),
    row("g14", Mode::Dynamic, 1314, 30, 30),
    row("g15", Mode::Dynamic, 1315, 20, 20),
    row("g17", Mode::Dynamic, 1316, 60, 90),
    row("g21", Mode::Dynamic, 1317, 40, 30),
    row("g23", Mode::Dynamic, 1318, 30, 30),
    row("g25", Mode::Dynamic, 1319, 40, 30),
    row("g26", Mode::Dynamic, 1320, 60, 60),
    row("g28", Mode::Dynamic, 1321, 20, 20),
    row("s1", Mode::Static, 1322, 0, 20),
    row("stale-rerender", Mode::Dynamic, 1323, 80, 90),
];

fn find_row(id: &str) -> &'static Row {
    ROWS.iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("{id} is a ROWS entry"))
}

/// The trail verifier reports zero violations after the run.
async fn assert_trail_clean(run: &FixtureRun) {
    let store = run.stores.memory.as_ref().expect("gym runs use the memory store");
    let report = verify_trail(
        run.report.run_id,
        TrailStore::Memory {
            store,
            artifacts: Some(run.stores.artifacts.as_ref()),
        },
    )
    .await
    .unwrap();
    assert!(report.is_clean(), "{}: {report}", run.manifest.id);
}

/// Fixture-relative page label of a URL: `path[?query]` with the `/<id>` prefix removed and
/// the entry page as `/` (the same labelling `rows_from_report` applies to states).
fn page_label(url: &url::Url, manifest: &FixtureManifest) -> String {
    let prefix = format!("/{}", manifest.id);
    let rel = url.path().strip_prefix(prefix.as_str()).unwrap_or(url.path());
    let rel = if rel.is_empty() { "/" } else { rel };
    match url.query() {
        Some(q) => format!("{rel}?{q}"),
        None => rel.to_owned(),
    }
}

/// Does observed page label `observed` show manifest page `page`: same path, and every query
/// pair of `page` present in `observed`'s query?
fn page_matches(page: &str, observed: &str) -> bool {
    let split = |s: &str| -> (String, BTreeSet<(String, String)>) {
        let (path, query) = s.split_once('?').unwrap_or((s, ""));
        let pairs = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        (path.to_owned(), pairs)
    };
    let (page_path, page_query) = split(page);
    let (seen_path, seen_query) = split(observed);
    page_path == seen_path && page_query.is_subset(&seen_query)
}

const fn mechanism_of(rung: crawlx_elements::Rung) -> Mechanism {
    match rung {
        crawlx_elements::Rung::Ax | crawlx_elements::Rung::Native => Mechanism::Ax,
        crawlx_elements::Rung::FocusCursor => Mechanism::Cursor,
        crawlx_elements::Rung::Listener => Mechanism::Listener,
    }
}

/// Harness labels from discovery passes in a fresh context over the pages the worker observed.
///
/// The worker's report carries action keys and states but not the candidate descriptors the
/// harness would label, so the discovery ladder (`CandidateDiscovery::discover`, the same
/// ladder the worker runs on every observation) is re-run here on the entry page and on every
/// manifest control page the run recorded a state or page for. Each candidate is labelled by
/// its DOM id against the manifest; its identity hash is built the way the worker's resolver
/// mints it (same `IdentityBuilder`, same destination canonicalization), so journaled action
/// keys map back to control ids. The entry page is also observed `reloads` more times and once
/// after the fixture's own rerender control (when it has one) for the identity rates.
struct Labels {
    /// Identity hash -> control id, for journaled action keys.
    by_hash: BTreeMap<crawlx_core::identity::ElementIdentityHash, String>,
    /// `(hash, logical id)` per labelled observation, for the collision/split rates.
    observations: Vec<(crawlx_core::identity::ElementIdentityHash, String)>,
    /// Candidates the ladder surfaced on the observed pages, labelled (`None` = false positive).
    surfaced: Vec<DiscoveredTarget>,
}

async fn labels(gym: &GymHandle, run: &FixtureRun, reloads: usize) -> Labels {
    let manifest = &run.manifest;
    let backend = launch().await.expect("have_chromium() was checked");
    let mut ctx = open_fixture(&backend, gym, manifest).await;
    let canon = CanonicalizeOptions::default();
    let mut labels = Labels {
        by_hash: BTreeMap::new(),
        observations: Vec::new(),
        surfaced: Vec::new(),
    };
    let mut surfaced_ids: BTreeSet<String> = BTreeSet::new();
    // one entry per distinct element on both sides: a control is a true positive once however
    // often it is observed, and an unlabelled element is one false positive, not one per reload
    let mut false_positives: BTreeSet<crawlx_core::identity::ElementIdentityHash> = BTreeSet::new();
    let mut label = |cands: &[crawlx_elements::Candidate], url: &url::Url, out: &mut Labels| {
        for c in cands {
            let control = dom_id(c).and_then(|id| manifest.control(id));
            let destination = IdentityBuilder::destination_key(&c.descriptor, url, &canon);
            let hash = IdentityBuilder::hash(&IdentityBuilder::build(&c.descriptor, destination)).unwrap();
            let Some(control) = control else {
                if false_positives.insert(hash) {
                    out.surfaced.push(DiscoveredTarget {
                        control: None,
                        mechanism: mechanism_of(c.rung),
                    });
                }
                continue;
            };
            let logical = control.logical_id.clone().unwrap_or_else(|| control.id.clone());
            out.by_hash.entry(hash).or_insert_with(|| control.id.clone());
            out.observations.push((hash, logical));
            if surfaced_ids.insert(control.id.clone()) {
                out.surfaced.push(DiscoveredTarget {
                    control: Some(control.id.clone()),
                    mechanism: mechanism_of(c.rung),
                });
            }
        }
    };
    let entry = canonical(&manifest.entry_url(&gym.base_url));
    let cands = discover(ctx.as_mut()).await;
    label(&cands, &entry.url, &mut labels);
    for _ in 0..reloads {
        ctx.navigate(&entry).await.unwrap();
        let cands = discover(ctx.as_mut()).await;
        label(&cands, &entry.url, &mut labels);
    }
    for rerender in ["rerender", "rerender-now"] {
        let cands = discover(ctx.as_mut()).await;
        if cands.iter().any(|c| dom_id(c) == Some(rerender)) {
            click(ctx.as_mut(), &cands, rerender).await;
            let cands = discover(ctx.as_mut()).await;
            label(&cands, &entry.url, &mut labels);
        }
    }
    // every manifest control page the worker observed (states or fetched pages), once; a
    // manifest page names its path and the query pairs that identify it (`/idp.html?client=gym`
    // matches the popup's `/idp.html?client=gym&redirect=…`)
    let observed: BTreeSet<String> = run
        .report
        .states
        .iter()
        .map(|s| page_label(&s.url.url, manifest))
        .chain(run.report.pages.iter().map(|p| page_label(&p.url.url, manifest)))
        .collect();
    let pages: BTreeSet<&str> = manifest
        .controls
        .iter()
        .filter_map(|c| c.page.as_deref())
        .map(|p| p.split('#').next().unwrap_or(p))
        .filter(|p| *p != "/" && observed.iter().any(|o| page_matches(p, o)))
        .collect();
    let base = gym.base_url.trim_end_matches('/');
    for page in pages {
        let url = canonical(&format!("{base}/{}{page}", manifest.id));
        ctx.navigate(&url).await.unwrap();
        let cands = discover(ctx.as_mut()).await;
        label(&cands, &url.url, &mut labels);
    }
    // identity labels (never discovery credit) for controls that exist only after one other
    // control was activated (`requires: [r]`): activate `r` on a fresh entry page and label what
    // it reveals, so journaled actions and learned enablement edges on revealed controls map
    // back to control ids
    let triggers: BTreeSet<&str> = manifest
        .controls
        .iter()
        .filter(|c| c.page.is_none() && c.requires.len() == 1)
        .map(|c| c.requires[0].as_str())
        .collect();
    for trigger in triggers {
        ctx.navigate(&entry).await.unwrap();
        let cands = discover(ctx.as_mut()).await;
        if !cands.iter().any(|c| dom_id(c) == Some(trigger)) {
            continue;
        }
        click(ctx.as_mut(), &cands, trigger).await;
        for c in discover(ctx.as_mut()).await {
            let Some(control) = dom_id(&c).and_then(|id| manifest.control(id)) else {
                continue;
            };
            if control.requires.iter().any(|r| r == trigger) {
                let destination = IdentityBuilder::destination_key(&c.descriptor, &entry.url, &canon);
                let hash =
                    IdentityBuilder::hash(&IdentityBuilder::build(&c.descriptor, destination)).unwrap();
                labels.by_hash.entry(hash).or_insert_with(|| control.id.clone());
            }
        }
    }
    ctx.close().await.unwrap();
    drop(backend);
    labels
}

/// Scorecard inputs of a worker run: `rows_from_report` (actions, claims, states, edges,
/// ledger-confirmed discovery) cross-checked against `RunRows::collect` from the persisted
/// stores, with the enablement edges labelled through the harness labels.
///
/// Discovery is widened from "the gym saw a click" (the lower bound `rows_from_report` uses)
/// to what the crawler surfaced: the ladder's candidates on the pages the worker observed
/// ([`Labels::surfaced`], false positives included) and every journaled action on a labelled
/// element (a control the kernel denied or whose click was dropped at revalidation was still
/// discovered). Controls that exist only after another action (`requires`) are never in
/// [`Labels::surfaced`]: they are credited through the ledger or through a journaled action on
/// them (the labelling pass reveals them only to map identities to control ids).
async fn scorecard_rows(run: &FixtureRun, gym: &GymHandle, seed: u64, labels: Option<&Labels>) -> RunRows {
    let mut rows = rows_from_report(
        &run.report,
        &run.manifest,
        seed,
        "quality-gate",
        SafetyProfile::TestEnvironment,
        gym,
    );
    let collected = RunRows::collect(
        run.report.run_id,
        &run.manifest.id,
        seed,
        "quality-gate",
        SafetyProfile::TestEnvironment,
        run.stores.journal.as_ref(),
        run.stores.edges.as_ref(),
        run.stores.ledger.as_ref(),
        run.stores.states.as_ref(),
    )
    .await
    .unwrap();
    assert_eq!(collected.actions.len(), rows.actions.len(), "{}", run.manifest.id);
    assert_eq!(collected.edges.len(), rows.edges.len(), "{}", run.manifest.id);
    if let Some(labels) = labels {
        let mut found: BTreeSet<String> = rows.discovered.iter().filter_map(|d| d.control.clone()).collect();
        let journaled = rows
            .actions
            .iter()
            .filter_map(|a| labels.by_hash.get(&a.key.element))
            .map(|control| DiscoveredTarget {
                control: Some(control.clone()),
                mechanism: Mechanism::Ax,
            });
        for d in labels.surfaced.iter().cloned().chain(journaled) {
            match &d.control {
                Some(control) if !found.insert(control.clone()) => {}
                _ => rows.discovered.push(d),
            }
        }
        rows.element_labels.clone_from(&labels.by_hash);
        rows.label_recorded_edges();
    }
    rows
}

/// Run one `ROWS` entry and assert every manifest threshold, the trail and (for `s1`) the
/// URL-plane counters.
async fn gate(id: &str) {
    let Row {
        mode,
        seed,
        interactions,
        seconds,
        ..
    } = *find_row(id);
    let crawl_mode = match mode {
        Mode::Static => CrawlMode::Static,
        Mode::Dynamic => {
            if !have_chromium() {
                return;
            }
            CrawlMode::Dynamic
        }
    };
    let _slot = browser_slot().await;
    let gym = gym().await;
    let run = run_fixture_with(&gym, id, crawl_mode, seed, interactions, |req| {
        req.limits.duration_seconds = seconds;
    })
    .await;
    let labels = match mode {
        Mode::Dynamic => Some(labels(&gym, &run, 3).await),
        Mode::Static => None,
    };
    let mut rows = scorecard_rows(&run, &gym, seed, labels.as_ref()).await;
    let expected = &run.manifest.expected;
    if let Some(labels) = &labels {
        if expected.collision_rate_max.is_some() || expected.split_rate_max.is_some() {
            rows.identity_observations.clone_from(&labels.observations);
            assert!(
                !rows.identity_observations.is_empty(),
                "{id}: no labelled control on the entry page"
            );
        }
    }
    let ledger = gym.ledger();
    let sc = Scorecard::compute(&run.manifest, &rows, &ledger);
    eprintln!("{}", sc.render_markdown());
    let clicked = ledger.clicked(id);
    eprintln!(
        "{id}: status={:?} reason={:?} exercised={} surfaced_only={} missed={:?} ops={} interactions={:?}",
        run.report.status,
        run.report.terminal_reason,
        clicked.len(),
        rows.discovered.len() - clicked.len(),
        sc.targets.missed,
        ledger.ops(id).len(),
        run.report.counters.interactions
    );
    assert_trail_clean(&run).await;
    let failing: Vec<String> = sc
        .checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| format!("{} expected {} got {}", c.name, c.expected, c.actual))
        .collect();
    assert!(
        failing.is_empty(),
        "{id}: failing checks: {failing:?}\n{}",
        sc.render_markdown()
    );
    assert_eq!(sc.safety.unauthorized, 0, "{id}: {:?}", sc.safety.violations);
    if let Some(counters) = expected.url_counters {
        assert_eq!(run.report.counters.urls, counters, "{id}: URL-plane counters");
    }
    gym.shutdown().await;
}

macro_rules! row_gates {
    ($($(#[$attr:meta])* $name:ident => $id:literal),* $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            $(#[$attr])*
            async fn $name() {
                gate($id).await;
            }
        )*
    };
}

row_gates! {
    row_a2_scorecard_passes => "a2",
    row_async_late_scorecard_passes => "async-late",
    row_div_buttons_scorecard_passes => "div-buttons",
    // the open modal restricts enumeration to the dialog, whose close control is withheld until
    // its other controls are exercised (escape policy), and revealed controls are followed
    // through (2026-10-20): measured target_recall 0.967 (58/60), target_precision 0.983,
    // enablement recall 1.00 (false edge rate 0.0); was 0.533 / 0.889
    row_g02_scorecard_passes => "g02",
    row_g03_scorecard_passes => "g03",
    row_g04_scorecard_passes => "g04",
    // the cross-origin `f3` OOPIF is auto-attached as its own session (2026-10-20): measured
    // target_recall 1.000 (36/36), target_precision 1.000, identity_collision_rate 0.0
    row_g05_scorecard_passes => "g05",
    row_g06_scorecard_passes => "g06",
    row_g07_scorecard_passes => "g07",
    row_g08_scorecard_passes => "g08",
    row_g12_scorecard_passes => "g12",
    // hover menus: the pointer stays in the menu wrapper, revealed items are followed through
    // and `enablement` replays the trigger for hidden ones (2026-10-20): measured
    // target_recall 1.000 (24/24), enablement recall 1.00 (false edge rate 0.0); was 0.250
    row_g13_scorecard_passes => "g13",
    // drag rung (grab cursor, `draggable`, drag/drop listeners) and `Intent::Drag` destinations
    // (2026-10-20): measured target_recall 1.000 (9/9; 6 drop hits in the gym ledger, the
    // other 3 surfaced as drag candidates); was 0.000
    row_g14_scorecard_passes => "g14",
    row_g15_scorecard_passes => "g15",
    // worker tab policy: switch to each attached popup, explore it, close it back to the opener
    // (2026-10-20): measured target_recall 1.000 (13/13, `profile` included: the OAuth round
    // trip completes through the IdP popup); was 0.538
    row_g17_scorecard_passes => "g17",
    row_g21_scorecard_passes => "g21",
    row_g23_scorecard_passes => "g23",
    row_g25_scorecard_passes => "g25",
    row_g26_scorecard_passes => "g26",
    row_g28_scorecard_passes => "g28",
    row_s1_scorecard_passes => "s1",
    row_stale_rerender_scorecard_passes => "stale-rerender",
}

// ---- hybrid-mix coverage ordering --------------------------------------------------

/// Reachable set of `hybrid-mix`: every page (URL-addressable or interaction-only, fragment
/// dropped) plus every control.
fn reachable(manifest: &FixtureManifest) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut pages: BTreeSet<String> = manifest.expected.url_addressable_pages.iter().cloned().collect();
    for c in &manifest.controls {
        let page = c.page.as_deref().unwrap_or("/");
        pages.insert(page.split('#').next().unwrap_or(page).to_owned());
    }
    let controls = manifest.controls.iter().map(|c| c.id.clone()).collect();
    (pages, controls)
}

/// Coverage of one run: `(pages reached ∪ controls exercised) / (reachable pages ∪ controls)`
/// where pages reached are the fixture pages the worker recorded (URL plane `pages` and
/// browser plane `states`, labelled by [`page_label`]) and controls exercised are the gym
/// ledger's clicked controls.
fn coverage(report: &RunReport, gym: &GymHandle, manifest: &FixtureManifest) -> (f64, usize, usize) {
    let (pages, controls) = reachable(manifest);
    let reached: BTreeSet<String> = report
        .pages
        .iter()
        .map(|p| page_label(&p.url.url, manifest))
        .chain(report.states.iter().map(|s| page_label(&s.url.url, manifest)))
        .filter(|p| pages.contains(p))
        .collect();
    let exercised: BTreeSet<String> = gym
        .ledger()
        .clicked(&manifest.id)
        .into_iter()
        .filter(|c| controls.contains(c))
        .collect();
    let hit = reached.len() + exercised.len();
    let total = pages.len() + controls.len();
    (hit as f64 / total as f64, reached.len(), exercised.len())
}

/// On `hybrid-mix` hybrid coverage is strictly above both static (URL
/// plane only: no control is ever exercised) and dynamic (browser only, same budget).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hybrid_mix_hybrid_coverage_beats_static_and_dynamic() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    let seed = 1_330;
    let mut measured = Vec::new();
    for mode in [CrawlMode::Static, CrawlMode::Dynamic, CrawlMode::Hybrid] {
        let gym = gym().await;
        let run = run_fixture(&gym, "hybrid-mix", mode, seed, 60).await;
        assert_trail_clean(&run).await;
        let (cov, pages, controls) = coverage(&run.report, &gym, &run.manifest);
        eprintln!("hybrid-mix {mode:?}: coverage={cov:.3} pages={pages} controls={controls}");
        measured.push((mode, cov));
        gym.shutdown().await;
    }
    let [(_, static_cov), (_, dynamic_cov), (_, hybrid_cov)] = measured[..] else {
        unreachable!()
    };
    assert!(
        hybrid_cov > static_cov.max(dynamic_cov),
        "hybrid {hybrid_cov:.3} must exceed static {static_cov:.3} and dynamic {dynamic_cov:.3}"
    );
}
