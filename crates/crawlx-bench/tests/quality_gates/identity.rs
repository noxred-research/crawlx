//! Identity stability on real Chromium (20 reloads per fixture):
//! G02 (ARIA widgets, `Rerender` rebuilds every widget with new non-semantic attributes)
//! and G06 (repeated cards, shuffled order and fresh counters on every render) are
//! reloaded and re-rendered 20 times each; every discovered control is hashed with
//! `IdentityBuilder` and labelled with the manifest's `logical_id`.
//!
//! Gates: `crawlx_elements::rates` collision ≤ 0.5 % and split ≤ 2 %, the manifest's
//! `collision_rate_max`/`split_rate_max` through the scorecard, the paper's exact-string
//! baseline reported side by side and never splitting less than
//! the weighted identity, and two independent contexts agreeing on ≥ 99 % of controls.
//! The ambiguity-band alias path is exercised offline against `MemoryStore`.

use super::common::*;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymHandle;
use crawlx_bench::scorecard::{RunRows, Scorecard};
use crawlx_browser::ChromiumBackend;
use crawlx_core::browser::BrowserContext;
use crawlx_core::config::SafetyProfile;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{IdentityAlias, IdentityAliasRepo, RunRepo};
use crawlx_core::ElementIdentityHash;
use crawlx_elements::normalize::is_wrapper_role;
use crawlx_elements::{rates, Candidate, IdentityBuilder};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::MemoryStore;
use crawlx_url::CanonicalizeOptions;
use std::collections::{BTreeMap, BTreeSet};

/// Reloads per fixture (planning default).
const RELOADS: usize = 20;
/// Fixture-level gates (identity-stability criterion).
const COLLISION_MAX: f64 = 0.005;
const SPLIT_MAX: f64 = 0.02;
/// Cross-session agreement floor.
const AGREEMENT_MIN: f64 = 0.99;

/// One labelled observation of a manifest control.
#[derive(Clone, Debug)]
struct Observation {
    /// `ElementIdentityV1` hash (weighted identity).
    weighted: ElementIdentityHash,
    /// The paper's exact-string key, hashed so `rates` can score it.
    baseline: ElementIdentityHash,
    /// Manifest `logical_id` (falls back to the control id).
    logical: String,
}

/// The paper's identity key: role + exact accessible
/// name + ancestor path with generic/group nodes filtered + container text truncated to 50
/// characters + the CDP frame id; links keyed by their `href` without the query.
fn paper_baseline(c: &Candidate) -> ElementIdentityHash {
    let d = &c.descriptor;
    let path: Vec<&str> = d
        .ancestor_roles
        .iter()
        .map(String::as_str)
        .filter(|r| !is_wrapper_role(r))
        .collect();
    let container: String = d
        .container_text
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(50)
        .collect();
    let href = d
        .href
        .as_deref()
        .map(|h| h.split_once('?').map_or(h, |(p, _)| p))
        .unwrap_or("");
    let key = format!(
        "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
        d.role,
        d.accessible_name.as_deref().or(d.text.as_deref()).unwrap_or(""),
        path.join(">"),
        container,
        d.locator.frame.0,
        href
    );
    ElementIdentityHash(Digest::of("crawlx/bench/paper-baseline", key.as_bytes()))
}

/// Label every candidate that is a manifest control.
fn label(manifest: &FixtureManifest, cands: &[Candidate], base: &url::Url) -> Vec<Observation> {
    cands
        .iter()
        .filter_map(|c| {
            let control = manifest.control(dom_id(c)?)?;
            let dest = IdentityBuilder::destination_key(&c.descriptor, base, &CanonicalizeOptions::default());
            let weighted = IdentityBuilder::hash(&IdentityBuilder::build(&c.descriptor, dest)).unwrap();
            Some(Observation {
                weighted,
                baseline: paper_baseline(c),
                logical: control.logical_id.clone().unwrap_or_else(|| control.id.clone()),
            })
        })
        .collect()
}

/// Click `id` after a fresh discovery (every G02 click redraws the page, so locators from
/// an earlier observation are stale).
async fn click_fresh(ctx: &mut dyn BrowserContext, id: &str) {
    let cands = discover(ctx).await;
    click(ctx, &cands, id).await;
}

/// How a fixture is driven through one round.
#[derive(Clone, Copy)]
struct Fixture {
    id: &'static str,
    /// Control that rebuilds the page in place.
    rerender: &'static str,
    /// Controls that expose gated widgets after a reload (G02: menu, combobox, tree); the
    /// opened state survives in-place rerenders.
    openers: &'static [&'static str],
    /// Modal opener and closer (observed in a separate pass: `aria-modal` prunes the rest).
    modal: Option<(&'static str, &'static str)>,
}

const G02: Fixture = Fixture {
    id: "g02",
    rerender: "tb-10",
    openers: &["cb", "tree-1", "tree-2", "tree-3", "menu-btn"],
    modal: Some(("dlg-open", "dlg-cancel")),
};

const G06: Fixture = Fixture {
    id: "g06",
    rerender: "rerender",
    openers: &[],
    modal: None,
};

/// Observe every manifest control of the current page state.
async fn observe_round(
    ctx: &mut dyn BrowserContext,
    fx: Fixture,
    manifest: &FixtureManifest,
) -> Vec<Observation> {
    let bundle = observe(ctx).await;
    let base = bundle.url.url.clone();
    let cands =
        crawlx_elements::CandidateDiscovery::discover(&bundle, &crawlx_elements::DiscoveryConfig::default());
    let mut out = label(manifest, &cands, &base);
    if let Some((open, close)) = fx.modal {
        click_fresh(ctx, open).await;
        let bundle = observe(ctx).await;
        let cands = crawlx_elements::CandidateDiscovery::discover(
            &bundle,
            &crawlx_elements::DiscoveryConfig::default(),
        );
        let seen: BTreeSet<String> = out.iter().map(|o| o.logical.clone()).collect();
        let modal_only: Vec<Observation> = label(manifest, &cands, &base)
            .into_iter()
            .filter(|o| !seen.contains(&o.logical))
            .collect();
        out.extend(modal_only);
        click_fresh(ctx, close).await;
    }
    out
}

/// `RELOADS` rounds over `fx` in one context: odd rounds navigate again (full reload, state
/// reset), even rounds use the in-place rerender control. Returns the labelled
/// observations of every round.
async fn reload_rounds(
    backend: &ChromiumBackend,
    gym: &GymHandle,
    fx: Fixture,
    manifest: &FixtureManifest,
) -> Vec<Vec<Observation>> {
    let mut ctx = open_fixture(backend, gym, manifest).await;
    let entry = canonical(&manifest.entry_url(&gym.base_url));
    let mut rounds = Vec::with_capacity(RELOADS);
    for r in 0..RELOADS {
        if r == 0 {
            // initial load: widgets closed
        } else if r % 2 == 1 {
            // full reload: page state reset, widgets closed again
            ctx.navigate(&entry).await.unwrap();
        } else {
            // in-place rerender: every widget rebuilt, opened state survives
            click_fresh(ctx.as_mut(), fx.rerender).await;
        }
        if r == 0 || r % 2 == 1 {
            for id in fx.openers {
                click_fresh(ctx.as_mut(), id).await;
            }
        }
        rounds.push(observe_round(ctx.as_mut(), fx, manifest).await);
    }
    ctx.close().await.unwrap();
    rounds
}

/// Collision/split of the weighted identity and the paper baseline over all rounds.
fn report(fx: Fixture, rounds: &[Vec<Observation>]) -> ((f64, f64), (f64, f64)) {
    let weighted: Vec<(ElementIdentityHash, String)> = rounds
        .iter()
        .flatten()
        .map(|o| (o.weighted, o.logical.clone()))
        .collect();
    let baseline: Vec<(ElementIdentityHash, String)> = rounds
        .iter()
        .flatten()
        .map(|o| (o.baseline, o.logical.clone()))
        .collect();
    let w = rates(&weighted);
    let b = rates(&baseline);
    let logical: BTreeSet<&str> = weighted.iter().map(|(_, l)| l.as_str()).collect();
    eprintln!(
        "{}: {} rounds, {} observations, {} logical controls\n  weighted identity: collision {:.4} split {:.4}\n  paper baseline:    collision {:.4} split {:.4}",
        fx.id,
        rounds.len(),
        weighted.len(),
        logical.len(),
        w.0,
        w.1,
        b.0,
        b.1
    );
    (w, b)
}

/// Every logical control observed under more than one hash, with the hashes, for diagnostics.
fn splits(rounds: &[Vec<Observation>]) -> BTreeMap<String, BTreeSet<ElementIdentityHash>> {
    let mut by_logical: BTreeMap<String, BTreeSet<ElementIdentityHash>> = BTreeMap::new();
    for o in rounds.iter().flatten() {
        by_logical
            .entry(o.logical.clone())
            .or_default()
            .insert(o.weighted);
    }
    by_logical.retain(|_, hs| hs.len() > 1);
    by_logical
}

/// Logical controls sharing a weighted hash, for diagnostics.
fn collisions(rounds: &[Vec<Observation>]) -> BTreeMap<ElementIdentityHash, BTreeSet<String>> {
    let mut by_hash: BTreeMap<ElementIdentityHash, BTreeSet<String>> = BTreeMap::new();
    for o in rounds.iter().flatten() {
        by_hash.entry(o.weighted).or_default().insert(o.logical.clone());
    }
    by_hash.retain(|_, ls| ls.len() > 1);
    by_hash
}

async fn reload_gate(fx: Fixture, seed: u64) {
    let _slot = browser_slot().await;
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    gym.reset(seed);
    let manifest = FixtureManifest::embedded(fx.id).unwrap();
    let rounds = reload_rounds(&backend, &gym, fx, &manifest).await;
    assert_eq!(rounds.len(), RELOADS);
    // entry-page controls only (G06's `item-back` lives on the item page)
    let expected: BTreeSet<&str> = manifest
        .controls
        .iter()
        .filter(|c| c.page.is_none())
        .map(|c| c.logical_id.as_deref().unwrap_or(c.id.as_str()))
        .collect();
    for (r, round) in rounds.iter().enumerate() {
        let seen: BTreeSet<&str> = round.iter().map(|o| o.logical.as_str()).collect();
        assert_eq!(
            seen, expected,
            "{}: round {r} exposes every logical control",
            fx.id
        );
    }
    let ((collision, split), (b_collision, b_split)) = report(fx, &rounds);
    assert!(
        collision <= COLLISION_MAX,
        "{}: collision {collision} > {COLLISION_MAX}: {:?}",
        fx.id,
        collisions(&rounds)
    );
    assert!(
        split <= SPLIT_MAX,
        "{}: split {split} > {SPLIT_MAX}: {:?}",
        fx.id,
        splits(&rounds)
    );
    assert!(
        b_split >= split,
        "{}: the paper baseline ({b_split}) must split at least as often as the weighted identity ({split})",
        fx.id
    );
    let _ = b_collision;

    // The manifest's own thresholds through the scorecard.
    let mut rows = RunRows::new(fx.id, seed, "identity-reloads", SafetyProfile::TestEnvironment);
    rows.identity_observations = rounds
        .iter()
        .flatten()
        .map(|o| (o.weighted, o.logical.clone()))
        .collect();
    let sc = Scorecard::compute(&manifest, &rows, &gym.ledger());
    let identity_checks: Vec<_> = sc
        .checks
        .iter()
        .filter(|c| c.name.starts_with("identity_"))
        .collect();
    assert_eq!(identity_checks.len(), 2, "{}", sc.render_markdown());
    assert!(
        identity_checks.iter().all(|c| c.passed),
        "{}",
        sc.render_markdown()
    );
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g02_twenty_reloads_and_rerenders_keep_identity_under_the_identity_gates() {
    reload_gate(G02, 4_002).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g06_twenty_reloads_and_rerenders_keep_identity_under_the_identity_gates() {
    reload_gate(G06, 4_006).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g02_paper_baseline_splits_at_least_as_often_as_the_weighted_identity_on_rerenders() {
    let _slot = browser_slot().await;
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    gym.reset(4_022);
    let manifest = FixtureManifest::embedded(G02.id).unwrap();
    // in-place rerenders only: the paper key carries the exact name and container text
    let mut ctx = open_fixture(&backend, &gym, &manifest).await;
    for id in G02.openers {
        click_fresh(ctx.as_mut(), id).await;
    }
    let mut rounds = Vec::with_capacity(RELOADS);
    for r in 0..RELOADS {
        if r > 0 {
            click_fresh(ctx.as_mut(), G02.rerender).await;
        }
        rounds.push(observe_round(ctx.as_mut(), G02, &manifest).await);
    }
    ctx.close().await.unwrap();
    let ((_, split), (_, b_split)) = report(G02, &rounds);
    assert!(
        b_split >= split,
        "baseline split {b_split} < weighted split {split}"
    );
    gym.shutdown().await;
}

/// Two independent contexts (fresh session ids, separate tabs) see the same fixture after
/// their own reloads; identities must agree for ≥ 99 % of logical controls.
async fn cross_session(fx: Fixture, seed: u64) {
    let _slot = browser_slot().await;
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    gym.reset(seed);
    let manifest = FixtureManifest::embedded(fx.id).unwrap();
    let mut per_session: Vec<BTreeMap<String, BTreeSet<ElementIdentityHash>>> = Vec::new();
    for s in 0..2u8 {
        let mut ctx = open_fixture(&backend, &gym, &manifest).await;
        // session B sees a different render of the same app
        for _ in 0..s {
            click_fresh(ctx.as_mut(), fx.rerender).await;
        }
        for id in fx.openers {
            click_fresh(ctx.as_mut(), id).await;
        }
        let round = observe_round(ctx.as_mut(), fx, &manifest).await;
        ctx.close().await.unwrap();
        let mut by_logical: BTreeMap<String, BTreeSet<ElementIdentityHash>> = BTreeMap::new();
        for o in round {
            by_logical.entry(o.logical).or_default().insert(o.weighted);
        }
        per_session.push(by_logical);
    }
    let (a, b) = (&per_session[0], &per_session[1]);
    let total = a.len();
    let agree = a.iter().filter(|(l, h)| b.get(*l) == Some(h)).count();
    let agreement = agree as f64 / total as f64;
    eprintln!(
        "{}: cross-session agreement {agree}/{total} = {agreement:.4}",
        fx.id
    );
    assert!(
        agreement >= AGREEMENT_MIN,
        "{}: cross-session agreement {agreement} < {AGREEMENT_MIN}",
        fx.id
    );
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g02_two_sessions_agree_on_at_least_99_percent_of_controls() {
    cross_session(G02, 4_102).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g06_two_sessions_agree_on_at_least_99_percent_of_controls() {
    cross_session(G06, 4_106).await;
}

/// An ambiguous-band resolution (`0.60 <= score < 0.80`, `MatchDecision::MintedNew { alias:
/// Some(_) }`) becomes an `identity_aliases` row with its score.
#[tokio::test]
async fn an_ambiguous_band_resolution_is_persisted_as_an_identity_alias() {
    use crawlx_core::epoch::ObservationEpoch;
    use crawlx_core::ids::{BackendNodeId, FrameId, TabId};
    use crawlx_core::observation::{BoundingBox, ObservedDescriptor, RuntimeLocator};
    use crawlx_core::TenantId;
    use crawlx_elements::{IdentityResolver, InMemoryIdentityIndex, MatchDecision, MatchWeights};

    let desc = |id: &str, name: &str, section: &str| ObservedDescriptor {
        locator: RuntimeLocator {
            tab: TabId("tab".into()),
            frame: FrameId("main".into()),
            backend_node_id: BackendNodeId(1),
            object_id: None,
            ax_node_id: None,
            epoch: ObservationEpoch::default(),
        },
        role: "button".into(),
        accessible_name: Some(name.into()),
        description: None,
        tag: Some("button".into()),
        attributes: BTreeMap::from([
            ("id".to_owned(), id.to_owned()),
            ("type".to_owned(), "button".to_owned()),
        ]),
        text: Some(name.into()),
        href: None,
        bbox: Some(BoundingBox {
            x: 10.0,
            y: 10.0,
            width: 100.0,
            height: 30.0,
        }),
        frame_lineage: Vec::new(),
        ancestor_roles: vec!["RootWebArea".into(), "main".into(), "region".into()],
        container_text: Some(format!("region|{section}")),
        focusable: true,
        disabled: false,
        visible: true,
        listeners: vec!["click".into()],
        cursor: Some("pointer".into()),
        in_closed_shadow_root: false,
        instance_ordinal: 0,
    };
    let resolver = IdentityResolver::new();
    let weights = MatchWeights::default();
    let mut index = InMemoryIdentityIndex::new();
    let known = resolver
        .resolve(&desc("add", "Add to cart", "Featured"), &index, &weights)
        .unwrap();
    index.record(&known);
    // same name and id in a differently named landmark: contradicting container evidence
    let minted = resolver
        .resolve(&desc("add", "Add to cart", "Clearance"), &index, &weights)
        .unwrap();
    let MatchDecision::MintedNew {
        best_score,
        alias: Some(alias_of),
    } = minted.decision
    else {
        panic!("expected an aliased mint, got {:?}", minted.decision)
    };
    assert!((0.60..0.80).contains(&best_score), "{best_score}");
    assert_eq!(alias_of, known.hash);

    let store = MemoryStore::new();
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&run, None).await.unwrap();
    let alias = IdentityAlias {
        alias: minted.hash,
        canonical: alias_of,
        from_version: 1,
        to_version: 1,
        score: best_score,
    };
    store.record_alias(run.id, &alias).await.unwrap();
    let stored = store.aliases_of(run.id, known.hash).await.unwrap();
    assert_eq!(stored, vec![alias]);
    assert!((stored[0].score - best_score).abs() < f32::EPSILON);
}
