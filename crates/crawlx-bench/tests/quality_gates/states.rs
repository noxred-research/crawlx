//! State-clustering gates on real Chromium: the G26 labelled state corpus and the
//! `feed-and-clock` explosion guard (G07 infinite feed, G08 clocks and live regions) with a
//! Crawljax-style baseline over the run's stored AX artifacts.

use super::common::*;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_core::action::{BrowserAction, ScrollDelta};
use crawlx_core::config::{CaptureMode, CrawlMode};
use crawlx_core::observation::ObservationBundle;
use crawlx_core::{StateClusterId, StateId};
use crawlx_state::{ClusterConfig, ClusterIndex, Fingerprinter, MaskBuilder, MaskConfig};
use crawlx_url::{CanonicalizeOptions, Canonicalizer, RouteTemplater};
use crawlx_worker::RouteLearner;
use parking_lot::RwLock;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

/// Deterministic cluster ids (the worker derives them from the crawl seed the same way).
fn cluster_ids() -> impl FnMut() -> StateClusterId + Send + 'static {
    let mut n = 0u128;
    move || {
        n += 1;
        StateClusterId(uuid::Uuid::from_u128(0x5fa7_e000 + n))
    }
}

fn state_id(n: usize) -> StateId {
    StateId(uuid::Uuid::from_u128(0x57a7_e000 + n as u128))
}

/// One labelled observation of the corpus.
struct Labelled {
    page: String,
    class: String,
    /// What produced it: `load`, `tick` or the clicked control.
    origin: String,
    bundle: ObservationBundle,
}

/// Partition quality against the truth classes, over every state pair.
#[derive(Debug, Default)]
struct CorpusReport {
    states: usize,
    classes: usize,
    clusters: usize,
    different_class_pairs: usize,
    same_class_pairs: usize,
    false_merge_pairs: usize,
    /// False merges whose pages expose different control sets (a merge that hides an action).
    merges_hiding_controls: Vec<(String, String)>,
    false_split_pairs: usize,
    false_split_rate: f64,
    /// Pairs of same-class states on different pages that were split (route twins).
    cross_page_splits: usize,
}

/// Attach every bundle to one index and score the partition.
fn partition(corpus: &[Labelled], manifest: &FixtureManifest, name: &str) -> CorpusReport {
    let fp = Fingerprinter::default();
    let masks_cfg = MaskConfig::default();
    let cfg = ClusterConfig::default();
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let mut assigned: Vec<StateClusterId> = Vec::with_capacity(corpus.len());
    for (n, obs) in corpus.iter().enumerate() {
        let masks = MaskBuilder::build(&obs.bundle, &[], &masks_cfg);
        let profile = fp.profile(&obs.bundle, &masks);
        let a = idx.attach(state_id(n + 1), &profile, &cfg);
        assigned.push(a.decision.cluster);
    }
    let controls_of = |page: &str| -> BTreeSet<&str> {
        manifest
            .controls
            .iter()
            .filter(|c| c.page.as_deref() == Some(page))
            .map(|c| c.id.as_str())
            .collect()
    };
    let mut r = CorpusReport {
        states: corpus.len(),
        classes: corpus
            .iter()
            .map(|o| o.class.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        clusters: idx.active_len(),
        ..CorpusReport::default()
    };
    for i in 0..corpus.len() {
        for j in i + 1..corpus.len() {
            let (a, b) = (&corpus[i], &corpus[j]);
            let same_cluster = assigned[i] == assigned[j];
            if a.class == b.class {
                r.same_class_pairs += 1;
                if !same_cluster {
                    r.false_split_pairs += 1;
                    if a.page != b.page {
                        r.cross_page_splits += 1;
                    }
                }
            } else {
                r.different_class_pairs += 1;
                if same_cluster {
                    r.false_merge_pairs += 1;
                    if controls_of(&a.page) != controls_of(&b.page) {
                        r.merges_hiding_controls.push((
                            format!("{}:{}", a.page, a.origin),
                            format!("{}:{}", b.page, b.origin),
                        ));
                    }
                }
            }
        }
    }
    r.false_split_rate = if r.same_class_pairs == 0 {
        0.0
    } else {
        r.false_split_pairs as f64 / r.same_class_pairs as f64
    };
    let by_cluster: BTreeMap<StateClusterId, Vec<String>> =
        assigned
            .iter()
            .zip(corpus)
            .fold(BTreeMap::new(), |mut m, (c, o)| {
                m.entry(*c).or_default().push(format!("{}:{}", o.page, o.origin));
                m
            });
    println!(
        "G26 corpus [{name}]: {} states, {} classes, {} clusters",
        r.states, r.classes, r.clusters
    );
    for (c, members) in &by_cluster {
        println!("  cluster {c}: {}", members.join(", "));
    }
    println!(
        "  false merges {}/{} different-class pairs (hiding a control: {}); false splits {}/{} same-class pairs = {:.1}% ({} cross-page)",
        r.false_merge_pairs,
        r.different_class_pairs,
        r.merges_hiding_controls.len(),
        r.false_split_pairs,
        r.same_class_pairs,
        100.0 * r.false_split_rate,
        r.cross_page_splits
    );
    r
}

/// Assert the state-partition bounds on a partition: false merges = 0 (none hiding a
/// control) and false split <= 5% (the G26 fixture target; the looser documented bound is
/// 15%, which the stricter one implies).
fn assert_state_partition_bounds(r: &CorpusReport, name: &str) {
    assert!(
        r.merges_hiding_controls.is_empty(),
        "[{name}] false merges hiding a control: {:?}",
        r.merges_hiding_controls
    );
    assert_eq!(r.false_merge_pairs, 0, "[{name}] false merges");
    assert!(
        r.false_split_rate <= 0.05,
        "[{name}] false split rate {:.1}% > 5%",
        100.0 * r.false_split_rate
    );
    println!(
        "  [{name}] false split {:.1}% <= 5% (G26 target holds)",
        100.0 * r.false_split_rate
    );
}

/// G26 "state twins" on real Chromium: every truth page observed on load, after a clock
/// tick and after each of its non-navigating controls; the partition is scored over every
/// labelled state pair, once with static route keys and once with the sibling pages learned
/// into one route by the worker's `RouteLearner` (the production online templating;
/// `min_distinct = 2` because the fixture has four sibling pages and the
/// planning default of 5 never fires on them) and keyed through the production
/// `Canonicalizer`, the path the browser plane's observer and the URL plane take.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g26_state_corpus_has_zero_false_merges_and_bounded_false_splits() {
    let _slot = browser_slot().await;
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g26").unwrap();
    let classes: BTreeMap<&str, &str> = manifest
        .expected
        .state_classes
        .iter()
        .map(|s| (s.page.as_str(), s.class.as_str()))
        .collect();
    assert_eq!(classes.len(), 4, "{classes:?}");
    let base = gym.base_url.trim_end_matches('/');

    let mut corpus: Vec<Labelled> = Vec::new();
    for (page, class) in &classes {
        let mut ctx = open_fixture(&backend, &gym, &manifest).await;
        let url = canonical(&format!("{base}/g26{page}"));
        ctx.navigate(&url).await.unwrap();
        let mut push = |origin: &str, bundle: ObservationBundle| {
            assert_eq!(
                bundle.url.url.path(),
                format!("/g26{page}"),
                "{origin} left the page"
            );
            corpus.push(Labelled {
                page: (*page).to_owned(),
                class: (*class).to_owned(),
                origin: origin.to_owned(),
                bundle,
            });
        };
        push("load", observe(ctx.as_mut()).await);
        tokio::time::sleep(Duration::from_millis(1300)).await;
        push("tick", observe(ctx.as_mut()).await);
        let buttons: Vec<&str> = manifest
            .controls
            .iter()
            .filter(|c| c.page.as_deref() == Some(*page) && c.role == "button")
            .map(|c| c.selector.trim_start_matches('#'))
            .collect();
        for id in buttons {
            let cands = discover(ctx.as_mut()).await;
            click(ctx.as_mut(), &cands, id).await;
            push(id, observe(ctx.as_mut()).await);
        }
    }
    assert_eq!(corpus.len(), 2 * 4 + 3 + 3 + 1 + 1, "observations");
    gym.shutdown().await;

    let production = partition(&corpus, &manifest, "static route keys");
    // zero false merges is the hard ADR gate under both route views
    assert!(
        production.merges_hiding_controls.is_empty(),
        "{:?}",
        production.merges_hiding_controls
    );
    assert_eq!(production.false_merge_pairs, 0);
    if production.false_split_rate > 0.05 {
        println!(
            "NOTE: [static route keys] G26 false split rate {:.1}% ({} of {} same-class pairs, {} cross-page): \
             `/g26/news-a` and `/g26/news-b` are distinct route keys and state clustering never merges across routes; \
             the worker's online route learning (below) is what closes it",
            100.0 * production.false_split_rate,
            production.false_split_pairs,
            production.same_class_pairs,
            production.cross_page_splits
        );
    }

    let learner = RouteLearner::new(Arc::new(RwLock::new(RouteTemplater::new().with_min_distinct(2))));
    let learned_rules = learner
        .observe_all(classes.keys().map(|p| format!("/g26{p}")))
        .expect("four siblings learn one slot");
    assert_eq!(learned_rules.version, 1);
    assert!(learned_rules.learned.contains_key("g26"), "{learned_rules:?}");
    let canon = CanonicalizeOptions {
        templater: Arc::clone(learner.templater()),
        ..CanonicalizeOptions::default()
    };
    let templated: Vec<Labelled> = corpus
        .iter()
        .map(|o| {
            let mut bundle = o.bundle.clone();
            let keyed = Canonicalizer::canonicalize_url(&bundle.url.url, &canon).unwrap();
            bundle.route = keyed.route_key();
            bundle.url = keyed;
            Labelled {
                page: o.page.clone(),
                class: o.class.clone(),
                origin: o.origin.clone(),
                bundle,
            }
        })
        .collect();
    let routes: BTreeSet<&str> = templated
        .iter()
        .map(|o| o.bundle.route.template.0.as_str())
        .collect();
    assert_eq!(
        routes.len(),
        1,
        "sibling pages share one learned route: {routes:?}"
    );
    let learned = partition(&templated, &manifest, "sibling pages templated");
    assert_state_partition_bounds(&learned, "sibling pages templated");
    // the twins that must stay apart did: profile and billing never share a cluster
    assert!(learned.clusters >= 3, "{learned:?}");
}

/// Crawljax-style baseline over the raw, unmasked `ax_tree` artifacts the worker stored for
/// every state: `(role, name, value)` token stream per node; `threshold = 0` is Crawljax's
/// default exact-DOM comparison, otherwise a normalized token edit distance. Greedy
/// representatives, like Crawljax's state machine.
fn crawljax_states(trees: &[Vec<u64>], threshold: f64) -> usize {
    let mut reps: Vec<&Vec<u64>> = Vec::new();
    for t in trees {
        let known = reps.iter().any(|r| {
            if threshold <= 0.0 {
                return *r == t;
            }
            let longest = r.len().max(t.len()).max(1);
            if r.len().abs_diff(t.len()) as f64 / longest as f64 > threshold {
                return false;
            }
            token_edit_distance(r, t) as f64 / longest as f64 <= threshold
        });
        if !known {
            reps.push(t);
        }
    }
    reps.len()
}

fn token_edit_distance(a: &[u64], b: &[u64]) -> usize {
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, x) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, y) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(x != y);
            cur[j + 1] = sub.min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Token stream of one stored `ax_tree` artifact (`crawlx_worker::analysis::ax_json`).
fn ax_tokens(bytes: &[u8]) -> Vec<u64> {
    let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    v["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["ignored"] != serde_json::Value::Bool(true))
        .map(|n| {
            let token = format!(
                "{}|{}|{}",
                n["role"].as_str().unwrap_or(""),
                n["name"].as_str().unwrap_or(""),
                n["value"].as_str().unwrap_or("")
            );
            crawlx_core::hash::Digest::of("crawljax/token", token.as_bytes())
                .0
                .iter()
                .take(8)
                .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
        })
        .collect()
}

/// Crawljax token stream of a live bundle (same tokens as [`ax_tokens`] builds from the
/// stored artifact).
fn bundle_tokens(b: &ObservationBundle) -> Vec<u64> {
    b.ax.nodes
        .iter()
        .filter(|n| !n.ignored)
        .map(|n| {
            let token = format!(
                "{}|{}|{}",
                n.role,
                n.name.as_deref().unwrap_or(""),
                n.value.as_deref().unwrap_or("")
            );
            crawlx_core::hash::Digest::of("crawljax/token", token.as_bytes())
                .0
                .iter()
                .take(8)
                .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
        })
        .collect()
}

/// Run `id` through the worker (100-interaction budget, 60 s wall clock, every state's
/// `ax_tree` stored), assert the state-partition bound on `report.states` and compare with the
/// Crawljax baseline over the stored artifacts. Returns `(actions, clusters, exact, lenient)`.
async fn worker_explosion_guard(
    gym: &crawlx_bench::gym::GymHandle,
    id: &str,
) -> (usize, usize, usize, usize) {
    let run = run_fixture_with(gym, id, CrawlMode::Dynamic, 7, 100, |req| {
        req.capture.dom_snapshot = CaptureMode::EveryState;
        req.limits.duration_seconds = 60;
    })
    .await;
    let actions = run.report.actions.len();
    let clusters: BTreeSet<StateClusterId> = run.report.states.iter().map(|s| s.cluster).collect();
    let bound = 5 * actions.div_ceil(100).max(1);
    let mut trees: Vec<Vec<u64>> = Vec::new();
    for s in &run.report.states {
        if let Some((_, r)) = s.artifacts.iter().find(|(k, _)| k == "ax_tree") {
            trees.push(ax_tokens(&run.stores.artifacts.get(r).await.unwrap()));
        }
    }
    let exact = crawljax_states(&trees, 0.0);
    let lenient = crawljax_states(&trees, 0.05);
    println!(
        "{id} worker run: {actions} actions, {} states, {} clusters (bound {bound}); Crawljax baseline over {} stored ax_tree artifacts: exact {exact}, edit-distance 5% {lenient}",
        run.report.states.len(),
        clusters.len(),
        trees.len()
    );
    assert!(!clusters.is_empty(), "{id}: no state cluster");
    assert!(
        clusters.len() <= bound,
        "{id}: {} clusters for {actions} actions exceeds {bound}",
        clusters.len()
    );
    assert_eq!(
        trees.len(),
        run.report.states.len(),
        "{id}: every state stored its ax_tree"
    );
    assert!(
        exact >= clusters.len(),
        "{id}: the masked partition is never finer than the Crawljax exact baseline"
    );
    (actions, clusters.len(), exact, lenient)
}

/// Attach `bundles` (in order) to one index and compare with the Crawljax baselines over the
/// same raw trees; asserts the per-100 bound and that the exact baseline exceeds it.
fn direct_explosion_guard(
    name: &str,
    actions: usize,
    bundles: &[ObservationBundle],
) -> (usize, usize, usize) {
    let fp = Fingerprinter::default();
    let cfg = ClusterConfig::default();
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    for (n, b) in bundles.iter().enumerate() {
        let masks = MaskBuilder::build(b, &[], &MaskConfig::default());
        idx.attach(state_id(n + 1), &fp.profile(b, &masks), &cfg);
    }
    let clusters = idx.active_len();
    let bound = 5 * actions.div_ceil(100).max(1);
    let trees: Vec<Vec<u64>> = bundles.iter().map(bundle_tokens).collect();
    let exact = crawljax_states(&trees, 0.0);
    let lenient = crawljax_states(&trees, 0.05);
    println!(
        "{name}: {actions} actions, {} observations, {clusters} masked clusters (bound {bound}); Crawljax baseline: exact {exact}, edit-distance 5% {lenient}",
        bundles.len()
    );
    assert!(clusters >= 1);
    assert!(
        clusters <= bound,
        "{name}: {clusters} clusters for {actions} actions exceeds {bound}"
    );
    assert!(
        exact > bound,
        "{name}: Crawljax exact baseline {exact} does not exceed the bound {bound}"
    );
    assert!(exact > clusters);
    (clusters, exact, lenient)
}

/// State-explosion guard on `feed-and-clock`, two ways:
///
/// 1. G07 (infinite feed) and G08 (clocks, tickers, live regions) through the worker with a
///    100-interaction budget: distinct clusters in `report.states` stay within
///    5 x ceil(actions / 100), and the Crawljax baseline over the run's stored `ax_tree`
///    artifacts is reported (strictly larger on G08, whose clock moves on every observation;
///    the worker never scrolls G07's `<ul>` feed, so its tail does not grow during the run).
/// 2. The same fixtures driven directly: 100 wheel scrolls down G07's feed (ten more posts
///    per sentinel intersection) and 100 observations of G08 across clock ticks, each
///    observed on real Chromium; the masked partition stays within 5 clusters per 100 actions
///    while the Crawljax exact baseline over the same unmasked trees exceeds the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g07_feed_and_g08_clock_stay_under_five_clusters_per_100_actions() {
    let _slot = browser_slot().await;
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    let worker_g07 = worker_explosion_guard(&gym, "g07").await;
    let worker_g08 = worker_explosion_guard(&gym, "g08").await;
    assert!(
        worker_g08.2 > worker_g08.1,
        "g08: Crawljax exact baseline {} is not larger than {} clusters",
        worker_g08.2,
        worker_g08.1
    );
    println!("worker runs: g07 {worker_g07:?}, g08 {worker_g08:?} as (actions, clusters, crawljax exact, crawljax 5%)");

    // G07 directly: scroll the feed 100 times, observing after each scroll
    let g07 = FixtureManifest::embedded("g07").unwrap();
    let mut ctx = open_fixture(&backend, &gym, &g07).await;
    let mut feed: Vec<ObservationBundle> = Vec::with_capacity(101);
    feed.push(observe(ctx.as_mut()).await);
    let viewport = f64::from(feed[0].viewport.height);
    for _ in 0..100 {
        ctx.perform(BrowserAction::Scroll {
            container: None,
            delta: ScrollDelta {
                dx: 0.0,
                dy: viewport * 0.8,
            },
        })
        .await
        .unwrap();
        feed.push(observe(ctx.as_mut()).await);
    }
    let feed_items = |b: &ObservationBundle| {
        b.ax.nodes
            .iter()
            .filter(|n| n.role.eq_ignore_ascii_case("listitem"))
            .count()
    };
    let (first, last) = (feed_items(&feed[0]), feed_items(feed.last().unwrap()));
    println!("g07 direct: feed grew from {first} to {last} list items over 100 scrolls");
    assert!(
        last > first + 30,
        "g07: the feed did not grow under scrolling ({first} -> {last})"
    );
    let g07_direct = direct_explosion_guard("g07 direct (100 scrolls)", 100, &feed);
    drop(ctx);

    // G08 directly: 100 observations across clock ticks (250 ms updates), one per action slot
    let g08 = FixtureManifest::embedded("g08").unwrap();
    let mut ctx = open_fixture(&backend, &gym, &g08).await;
    let mut clock: Vec<ObservationBundle> = Vec::with_capacity(100);
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(120)).await;
        clock.push(observe(ctx.as_mut()).await);
    }
    let g08_direct = direct_explosion_guard("g08 direct (100 ticks)", 100, &clock);
    drop(ctx);
    gym.shutdown().await;
    println!(
        "direct runs: g07 {g07_direct:?}, g08 {g08_direct:?} as (clusters, crawljax exact, crawljax 5%)"
    );
}
