//! Weight regression test: a committed corpus of labelled descriptor pairs
//! (`fixtures/corpora/identity_pairs.json`) keeps the weighted matcher's precision and
//! recall for the `same` class above the planning floors (0.99 / 0.97).
//!
//! The corpus is generated deterministically from the G02 (ARIA widgets) and G06 (repeated
//! cards) control templates of `crawlx-bench/fixtures/*/manifest.json` plus the structure
//! of those pages (ancestor roles, named containers, volatile attributes) and committed, so
//! this crate needs no bench dependency (layering forbids elements → bench). Regenerate with
//! `cargo test -p crawlx-elements --test weight_regression regenerate -- --ignored` after a
//! template change; a weight change must update the committed report.
//!
//! Each pair is resolved the way the crawler does: a fresh `InMemoryIdentityIndex` seeded with
//! the first descriptor, then the second resolved against it; `MatchDecision::Reused` predicts
//! `same`, a mint predicts `different`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::ids::{BackendNodeId, FrameId, TabId};
use crawlx_core::observation::{BoundingBox, ObservedDescriptor, RuntimeLocator};
use crawlx_core::seed::CrawlSeed;
use crawlx_elements::{IdentityResolver, InMemoryIdentityIndex, MatchDecision, MatchWeights};
use crawlx_url::CanonicalizeOptions;
use rand::seq::{IndexedRandom as _, SliceRandom as _};
use rand::RngExt as _;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Corpus path relative to this crate.
const CORPUS: &str = "fixtures/corpora/identity_pairs.json";
/// Seed the generator derives every random choice from.
const SEED: u64 = 4004;
/// Planning floors.
const PRECISION_MIN: f64 = 0.99;
const RECALL_MIN: f64 = 0.97;
/// Minimum corpus size.
const MIN_PAIRS: usize = 200;

#[derive(Serialize, Deserialize, Debug)]
struct Corpus {
    version: u32,
    seed: u64,
    sources: Vec<String>,
    pairs: Vec<Pair>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum Label {
    Same,
    Different,
}

#[derive(Serialize, Deserialize, Debug)]
struct Pair {
    label: Label,
    /// Perturbation family (`rerender_attrs`, `sibling_same_role`, ...).
    kind: String,
    /// Page URL the hrefs resolve against.
    page: String,
    a: Desc,
    b: Desc,
}

/// JSON mirror of the identity-relevant part of `ObservedDescriptor` (the runtime locator is
/// epoch-bound and never part of identity).
#[derive(Clone, Serialize, Deserialize, Debug)]
struct Desc {
    role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accessible_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attributes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    href: Option<String>,
    /// `[x, y, width, height]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bbox: Option<[f64; 4]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    frame_lineage: Vec<String>,
    ancestor_roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    container_text: Option<String>,
    #[serde(default)]
    instance_ordinal: u32,
}

impl Desc {
    fn observed(&self, backend: i64) -> ObservedDescriptor {
        ObservedDescriptor {
            locator: RuntimeLocator {
                tab: TabId("corpus".into()),
                frame: FrameId("main".into()),
                backend_node_id: BackendNodeId(backend),
                object_id: None,
                ax_node_id: None,
                epoch: ObservationEpoch::default(),
            },
            role: self.role.clone(),
            accessible_name: self.accessible_name.clone(),
            description: None,
            tag: self.tag.clone(),
            attributes: self.attributes.clone(),
            text: self.text.clone(),
            href: self.href.clone(),
            bbox: self
                .bbox
                .map(|[x, y, width, height]| BoundingBox { x, y, width, height }),
            frame_lineage: self.frame_lineage.clone(),
            ancestor_roles: self.ancestor_roles.clone(),
            container_text: self.container_text.clone(),
            focusable: true,
            disabled: false,
            visible: true,
            listeners: vec!["click".into()],
            cursor: Some("pointer".into()),
            in_closed_shadow_root: false,
            instance_ordinal: self.instance_ordinal,
        }
    }
}

fn corpus_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS)
}

/// Resolve `b` against an index seeded with `a`; `true` when the matcher reuses `a`'s identity.
fn predicted_same(pair: &Pair, version: crawlx_core::config::IdentityVersion) -> bool {
    let resolver = IdentityResolver::with_destination(
        url::Url::parse(&pair.page).unwrap(),
        CanonicalizeOptions::default(),
    )
    .with_identity_version(version, "en");
    let weights = MatchWeights::default();
    let mut index = InMemoryIdentityIndex::new();
    let seeded = resolver.resolve(&pair.a.observed(1), &index, &weights).unwrap();
    index.record(&seeded);
    let resolved = resolver.resolve(&pair.b.observed(2), &index, &weights).unwrap();
    matches!(resolved.decision, MatchDecision::Reused { .. })
}

#[derive(Default, Debug)]
struct Confusion {
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
    /// Misclassified pairs by kind, for the report.
    misses: BTreeMap<String, usize>,
}

fn confusion(corpus: &Corpus) -> Confusion {
    let mut c = Confusion::default();
    for p in &corpus.pairs {
        match (
            p.label,
            predicted_same(p, crawlx_core::config::IdentityVersion::V1),
        ) {
            (Label::Same, true) => c.tp += 1,
            (Label::Same, false) => {
                c.fn_ += 1;
                *c.misses.entry(format!("false split: {}", p.kind)).or_default() += 1;
            }
            (Label::Different, true) => {
                c.fp += 1;
                *c.misses.entry(format!("false merge: {}", p.kind)).or_default() += 1;
            }
            (Label::Different, false) => c.tn += 1,
        }
    }
    c
}

#[test]
fn v2_keeps_all_353_pairs_at_perfect_precision_and_recall() {
    let corpus: Corpus =
        serde_json::from_str(&std::fs::read_to_string(corpus_path()).expect("committed corpus")).unwrap();
    assert_eq!(corpus.pairs.len(), 353);
    let mut same = 0;
    let mut different = 0;
    for pair in &corpus.pairs {
        assert_eq!(
            predicted_same(pair, crawlx_core::config::IdentityVersion::V2),
            pair.label == Label::Same,
            "V2 regression: {} {:?}",
            pair.kind,
            pair.label,
        );
        match pair.label {
            Label::Same => same += 1,
            Label::Different => different += 1,
        }
    }
    assert_eq!((same, different), (225, 128));
}

#[test]
fn the_weighted_matcher_keeps_precision_and_recall_above_the_planning_floors() {
    let text = std::fs::read_to_string(corpus_path()).expect("committed corpus");
    let corpus: Corpus = serde_json::from_str(&text).unwrap();
    assert!(
        corpus.pairs.len() >= MIN_PAIRS,
        "corpus has {} pairs (< {MIN_PAIRS})",
        corpus.pairs.len()
    );
    let c = confusion(&corpus);
    let precision = c.tp as f64 / (c.tp + c.fp) as f64;
    let recall = c.tp as f64 / (c.tp + c.fn_) as f64;
    let mut kinds: BTreeMap<(Label, &str), usize> = BTreeMap::new();
    for p in &corpus.pairs {
        *kinds.entry((p.label, p.kind.as_str())).or_default() += 1;
    }
    eprintln!(
        "identity_pairs.json: {} pairs ({} same, {} different) with MatchWeights::default()\n  confusion: tp {} fp {} fn {} tn {}\n  precision {precision:.4} recall {recall:.4}\n  kinds: {kinds:?}\n  misses: {:?}",
        corpus.pairs.len(),
        c.tp + c.fn_,
        c.fp + c.tn,
        c.tp,
        c.fp,
        c.fn_,
        c.tn,
        c.misses
    );
    assert!(
        precision >= PRECISION_MIN,
        "precision {precision} < {PRECISION_MIN}: {:?}",
        c.misses
    );
    assert!(
        recall >= RECALL_MIN,
        "recall {recall} < {RECALL_MIN}: {:?}",
        c.misses
    );
}

#[test]
fn the_corpus_is_what_the_generator_produces() {
    let committed = std::fs::read_to_string(corpus_path()).expect("committed corpus");
    let parsed: Corpus = serde_json::from_str(&committed).unwrap();
    assert_eq!((parsed.seed, parsed.version), (SEED, gen::VERSION));
    // the generator needs the bench manifests; skip the comparison when the checkout does not
    // carry them (the committed corpus is still validated above)
    let Some(regenerated) = gen::generate() else {
        eprintln!("SKIP: bench fixture manifests not found; corpus not cross-checked");
        return;
    };
    let mut regenerated = serde_json::to_string_pretty(&regenerated).unwrap();
    regenerated.push('\n');
    if regenerated != committed {
        let first = regenerated
            .lines()
            .zip(committed.lines())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        panic!(
            "corpus drifted from its generator at line {first} (regenerate with `cargo test -p crawlx-elements --test weight_regression regenerate -- --ignored`):\n  generated: {:?}\n  committed: {:?}",
            regenerated.lines().nth(first),
            committed.lines().nth(first)
        );
    }
}

#[test]
#[ignore = "regenerates fixtures/corpora/identity_pairs.json"]
fn regenerate() {
    let corpus = gen::generate().expect("bench fixture manifests at ../crawlx-bench/fixtures");
    let mut text = serde_json::to_string_pretty(&corpus).unwrap();
    text.push('\n');
    std::fs::write(corpus_path(), text).unwrap();
    eprintln!(
        "wrote {} pairs to {}",
        corpus.pairs.len(),
        corpus_path().display()
    );
}

/// The corpus generator: fixture templates plus the page structure of G02/G06.
mod gen {
    use super::*;

    pub const VERSION: u32 = 1;
    const SOURCES: [&str; 2] = ["g02/manifest.json", "g06/manifest.json"];

    /// A manifest control as the generator needs it.
    #[derive(Clone, Deserialize)]
    struct Control {
        id: String,
        role: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        page: Option<String>,
    }

    #[derive(Deserialize)]
    struct Manifest {
        id: String,
        url_path: String,
        controls: Vec<Control>,
    }

    /// A control template with its position in the fixture page.
    #[derive(Clone)]
    struct Template {
        fixture: String,
        page: String,
        control: Control,
        /// Group of siblings sharing one role and container (tabs, menu items, ...).
        group: String,
        /// Index inside its group (document order).
        ordinal: u32,
        base: Desc,
    }

    fn manifests() -> Option<Vec<Manifest>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crawlx-bench/fixtures");
        SOURCES
            .iter()
            .map(|s| {
                let text = std::fs::read_to_string(root.join(s)).ok()?;
                serde_json::from_str(&text).ok()
            })
            .collect()
    }

    fn roles(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn attrs(list: &[(&str, &str)]) -> BTreeMap<String, String> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// Leading non-digit part of an id up to its last `-`: `tab-3` → `tab`, `tree-2-1` → `tree-2`.
    fn group_of(id: &str) -> String {
        id.rsplit_once('-')
            .filter(|(_, n)| n.chars().all(|c| c.is_ascii_digit()))
            .map_or(id, |(g, _)| g)
            .to_owned()
    }

    fn ordinal_of(id: &str) -> u32 {
        id.rsplit_once('-').and_then(|(_, n)| n.parse().ok()).unwrap_or(0)
    }

    /// Page structure of a G02 control (`index.html`): tag, attributes, ancestors (outermost
    /// first, wrappers included as the AX tree reports them) and the nearest named container.
    fn g02_structure(c: &Control) -> Desc {
        let id = c.id.as_str();
        let name = c.name.clone();
        let group = group_of(id);
        let n = ordinal_of(id);
        let (tag, extra, ancestors, container): (&str, Vec<(String, String)>, Vec<&str>, &str) =
            match group.as_str() {
                "tab" => (
                    "div",
                    vec![
                        ("role".into(), "tab".into()),
                        ("tabindex".into(), "-1".into()),
                        ("aria-selected".into(), "false".into()),
                        ("aria-controls".into(), format!("panel-{n}")),
                    ],
                    vec!["RootWebArea", "region", "tablist"],
                    "tablist|Sections",
                ),
                "menu-btn" => (
                    "div",
                    vec![
                        ("role".into(), "button".into()),
                        ("tabindex".into(), "0".into()),
                        ("aria-haspopup".into(), "menu".into()),
                        ("aria-expanded".into(), "false".into()),
                        ("aria-controls".into(), "menu".into()),
                    ],
                    vec!["RootWebArea", "region", "generic"],
                    "region|Menu",
                ),
                "menu" => (
                    "li",
                    vec![
                        ("role".into(), "menuitem".into()),
                        ("tabindex".into(), "-1".into()),
                    ],
                    vec!["RootWebArea", "region", "generic", "menu"],
                    "menu|Actions",
                ),
                "cb" => (
                    "div",
                    vec![
                        ("role".into(), "combobox".into()),
                        ("tabindex".into(), "0".into()),
                        ("aria-haspopup".into(), "listbox".into()),
                        ("aria-expanded".into(), "false".into()),
                        ("aria-controls".into(), "cb-list".into()),
                        ("aria-label".into(), "Fruit".into()),
                    ],
                    vec!["RootWebArea", "region", "generic"],
                    "region|Combobox",
                ),
                "cb-opt" => (
                    "li",
                    vec![
                        ("role".into(), "option".into()),
                        ("aria-selected".into(), "false".into()),
                    ],
                    vec!["RootWebArea", "region", "generic", "listbox"],
                    "listbox|Fruit options",
                ),
                "lb-opt" => (
                    "li",
                    vec![
                        ("role".into(), "option".into()),
                        ("aria-selected".into(), "false".into()),
                    ],
                    vec!["RootWebArea", "region", "listbox"],
                    "listbox|Colors",
                ),
                "tree" => (
                    "li",
                    vec![
                        ("role".into(), "treeitem".into()),
                        ("aria-expanded".into(), "false".into()),
                        ("tabindex".into(), "-1".into()),
                    ],
                    vec!["RootWebArea", "region", "tree"],
                    "tree|Navigation",
                ),
                g if g.starts_with("tree-") => (
                    "li",
                    vec![
                        ("role".into(), "treeitem".into()),
                        ("tabindex".into(), "-1".into()),
                    ],
                    vec!["RootWebArea", "region", "tree", "treeitem", "group"],
                    "tree|Navigation",
                ),
                "dlg-open" => (
                    "div",
                    vec![
                        ("role".into(), "button".into()),
                        ("tabindex".into(), "0".into()),
                        ("aria-haspopup".into(), "dialog".into()),
                    ],
                    vec!["RootWebArea", "region"],
                    "region|Dialog",
                ),
                "dlg-confirm" | "dlg-cancel" | "dlg-help" => (
                    "div",
                    vec![("role".into(), "button".into()), ("tabindex".into(), "0".into())],
                    vec!["RootWebArea", "region", "dialog"],
                    "dialog|Confirm",
                ),
                "tb" => (
                    "div",
                    vec![("role".into(), "button".into()), ("tabindex".into(), "0".into())],
                    vec!["RootWebArea", "region", "toolbar"],
                    "toolbar|Formatting",
                ),
                other => panic!("unknown g02 control group {other} ({id})"),
            };
        let mut attributes: BTreeMap<String, String> = extra.into_iter().collect();
        attributes.insert("id".into(), id.to_owned());
        attributes.insert("class".into(), "r0".into());
        attributes.insert("data-render".into(), "0".into());
        Desc {
            role: c.role.clone(),
            accessible_name: name.clone(),
            tag: Some(tag.into()),
            attributes,
            text: name,
            href: None,
            bbox: None,
            frame_lineage: Vec::new(),
            ancestor_roles: roles(&ancestors),
            container_text: Some(container.into()),
            instance_ordinal: 0,
        }
    }

    /// Page structure of a G06 entry-page control (`index.html`).
    fn g06_structure(c: &Control) -> Desc {
        let id = c.id.as_str();
        let n = ordinal_of(id);
        let group = group_of(id);
        match group.as_str() {
            "rerender" => Desc {
                role: "button".into(),
                accessible_name: Some("Rerender".into()),
                tag: Some("button".into()),
                attributes: attrs(&[("id", "rerender"), ("type", "button")]),
                text: Some("Rerender".into()),
                href: None,
                bbox: None,
                frame_lineage: Vec::new(),
                ancestor_roles: roles(&["RootWebArea"]),
                container_text: Some("heading|Cards".into()),
                instance_ordinal: 0,
            },
            "like" => Desc {
                role: "button".into(),
                accessible_name: Some("Like (0)".into()),
                tag: Some("button".into()),
                attributes: attrs(&[("id", id), ("type", "button")]),
                text: Some("Like (0)".into()),
                href: None,
                bbox: None,
                frame_lineage: Vec::new(),
                ancestor_roles: roles(&["RootWebArea", "list", "listitem", "article"]),
                container_text: Some(format!("heading|Card {n}")),
                instance_ordinal: 0,
            },
            "open" => Desc {
                role: "link".into(),
                accessible_name: Some("Open".into()),
                tag: Some("a".into()),
                attributes: attrs(&[("id", id), ("href", &format!("/g06/item?id={n}"))]),
                text: Some("Open".into()),
                href: Some(format!("/g06/item?id={n}")),
                bbox: None,
                frame_lineage: Vec::new(),
                ancestor_roles: roles(&["RootWebArea", "list", "listitem", "article"]),
                container_text: Some(format!("heading|Card {n}")),
                instance_ordinal: 0,
            },
            other => panic!("unknown g06 control group {other} ({id})"),
        }
    }

    /// Templates of both fixtures with their document-order geometry.
    fn templates(manifests: &[Manifest]) -> Vec<Template> {
        let mut out = Vec::new();
        for m in manifests {
            let page = format!("http://gym.test{}", m.url_path);
            let mut per_group: BTreeMap<String, u32> = BTreeMap::new();
            let mut row = 0.0f64;
            for c in m.controls.iter().filter(|c| c.page.is_none()) {
                row += 1.0;
                let mut base = match m.id.as_str() {
                    "g02" => g02_structure(c),
                    "g06" => g06_structure(c),
                    other => panic!("no structure for fixture {other}"),
                };
                let group = group_of(&c.id);
                let ordinal = {
                    let e = per_group.entry(group.clone()).or_default();
                    let o = *e;
                    *e += 1;
                    o
                };
                // one row per control, 40 px apart; siblings side by side in widgets that lay
                // them out horizontally (tabs, toolbar)
                let horizontal = matches!(group.as_str(), "tab" | "tb");
                base.bbox = Some(if horizontal {
                    [24.0 + 110.0 * f64::from(ordinal), 60.0 + 40.0 * row, 100.0, 32.0]
                } else {
                    [24.0, 60.0 + 40.0 * row, 160.0, 32.0]
                });
                base.instance_ordinal = ordinal;
                out.push(Template {
                    fixture: m.id.clone(),
                    page: page.clone(),
                    control: c.clone(),
                    group,
                    ordinal,
                    base,
                });
            }
        }
        out
    }

    // ---- perturbations ------------------------------------------------------------------

    fn drift(bbox: Option<[f64; 4]>, rng: &mut ChaCha8Rng, px: f64) -> Option<[f64; 4]> {
        bbox.map(|[x, y, w, h]| {
            [
                x + rng.random_range(-px..=px),
                y + rng.random_range(-px..=px),
                w,
                h,
            ]
        })
    }

    /// G02 `volatile()` / G06 `draw()`: new non-semantic attributes, a fresh counter in the
    /// name, a few pixels of layout drift.
    fn rerender(t: &Template, rng: &mut ChaCha8Rng, render: u32) -> Desc {
        let mut d = t.base.clone();
        if t.fixture == "g02" {
            d.attributes
                .insert("class".into(), format!("r{}", rng.random_range(0..1_000_000u32)));
            d.attributes.insert("data-render".into(), render.to_string());
        }
        if t.group == "like" {
            let name = format!("Like ({})", rng.random_range(0..500u32));
            d.accessible_name = Some(name.clone());
            d.text = Some(name);
        }
        d.bbox = drift(d.bbox, rng, 3.0);
        d
    }

    /// Extra generic wrappers between the control and its stable ancestors.
    fn wrapped(t: &Template, rng: &mut ChaCha8Rng) -> Desc {
        let mut d = t.base.clone();
        let extra = rng.random_range(1..=4usize);
        let at = rng.random_range(1..=d.ancestor_roles.len());
        for _ in 0..extra {
            let role = ["generic", "group", "none", "div"][rng.random_range(0..4usize)];
            d.ancestor_roles.insert(at, role.into());
        }
        d.bbox = drift(d.bbox, rng, 1.0);
        d
    }

    /// Sibling reorder (G02 toolbar shuffle, G06 card shuffle): the control takes another
    /// sibling's slot and ordinal.
    fn reordered(t: &Template, siblings: &[&Template], rng: &mut ChaCha8Rng) -> Desc {
        let mut d = t.base.clone();
        let other = siblings[rng.random_range(0..siblings.len())];
        d.bbox = other.base.bbox;
        d.instance_ordinal = other.ordinal;
        if t.group == "like" {
            let name = format!("Like ({})", rng.random_range(0..500u32));
            d.accessible_name = Some(name.clone());
            d.text = Some(name);
        }
        d
    }

    fn pair(label: Label, kind: &str, page: &str, a: Desc, b: Desc) -> Pair {
        Pair {
            label,
            kind: kind.to_owned(),
            page: page.to_owned(),
            a,
            b,
        }
    }

    pub fn generate() -> Option<Corpus> {
        let manifests = manifests()?;
        let templates = templates(&manifests);
        let mut rng = CrawlSeed(SEED).rng("identity-pairs", &[b"v1"]);
        let mut pairs = Vec::new();

        let by_group = |fixture: &str, group: &str| -> Vec<&Template> {
            templates
                .iter()
                .filter(|t| t.fixture == fixture && t.group == group)
                .collect()
        };
        let g02: Vec<&Template> = templates.iter().filter(|t| t.fixture == "g02").collect();
        let likes = by_group("g06", "like");
        let opens = by_group("g06", "open");

        // ---- same: every G02 control under the three rerender perturbations -------------
        for t in &g02 {
            let siblings = by_group("g02", &t.group);
            pairs.push(pair(
                Label::Same,
                "rerender_attrs",
                &t.page,
                t.base.clone(),
                rerender(t, &mut rng, 1),
            ));
            pairs.push(pair(
                Label::Same,
                "wrapper_depth",
                &t.page,
                rerender(t, &mut rng, 2),
                wrapped(t, &mut rng),
            ));
            pairs.push(pair(
                Label::Same,
                "sibling_reorder",
                &t.page,
                rerender(t, &mut rng, 3),
                reordered(t, &siblings, &mut rng),
            ));
        }
        // ---- same: G06 like buttons: counters in names, reorder, template ordinals -------
        let sampled_likes: Vec<&&Template> = likes.sample(&mut rng, 12).collect();
        for t in &sampled_likes {
            pairs.push(pair(
                Label::Same,
                "counter_in_name",
                &t.page,
                rerender(t, &mut rng, 1),
                rerender(t, &mut rng, 2),
            ));
            pairs.push(pair(
                Label::Same,
                "sibling_reorder",
                &t.page,
                rerender(t, &mut rng, 3),
                reordered(t, &likes, &mut rng),
            ));
            let other = likes[rng.random_range(0..likes.len())];
            pairs.push(pair(
                Label::Same,
                "template_ordinal",
                &t.page,
                rerender(t, &mut rng, 4),
                rerender(other, &mut rng, 4),
            ));
        }
        // the G06 rerender button and the Open template across cards (one destination
        // template `/g06/item?id=:id`, query classification)
        let rerender_btn = by_group("g06", "rerender")[0];
        pairs.push(pair(
            Label::Same,
            "rerender_attrs",
            &rerender_btn.page,
            rerender_btn.base.clone(),
            rerender(rerender_btn, &mut rng, 1),
        ));
        for t in opens.sample(&mut rng, 8) {
            let other = opens[rng.random_range(0..opens.len())];
            pairs.push(pair(
                Label::Same,
                "template_ordinal",
                &t.page,
                rerender(t, &mut rng, 1),
                reordered(other, &opens, &mut rng),
            ));
        }

        // ---- different: siblings of one role inside one widget ---------------------------
        let sibling_groups = [
            "tab",
            "menu",
            "cb-opt",
            "lb-opt",
            "tree",
            "tree-1",
            "tree-2",
            "tree-3",
            "tb",
            "dlg-confirm",
        ];
        let mut sibling_pairs = Vec::new();
        for g in sibling_groups {
            let members: Vec<&Template> = if g == "dlg-confirm" {
                g02.iter()
                    .copied()
                    .filter(|t| t.group.starts_with("dlg-") && t.group != "dlg-open")
                    .collect()
            } else {
                by_group("g02", g)
            };
            for (i, a) in members.iter().enumerate() {
                for b in &members[i + 1..] {
                    sibling_pairs.push((*a, *b));
                }
            }
        }
        sibling_pairs.shuffle(&mut rng);
        for (a, b) in sibling_pairs.iter().take(70) {
            pairs.push(pair(
                Label::Different,
                "sibling_same_role",
                &a.page,
                rerender(a, &mut rng, 1),
                rerender(b, &mut rng, 1),
            ));
        }
        // ---- different: same control template in another named landmark -----------------
        for t in g02.sample(&mut rng, 16) {
            let mut moved = rerender(t, &mut rng, 1);
            let container = moved.container_text.clone().unwrap();
            let (kind, _) = container.split_once('|').unwrap();
            moved.container_text = Some(format!("{kind}|Archived {}", t.group));
            pairs.push(pair(
                Label::Different,
                "same_name_other_container",
                &t.page,
                t.base.clone(),
                moved,
            ));
        }
        for t in likes.sample(&mut rng, 4) {
            let mut moved = rerender(t, &mut rng, 1);
            moved.ancestor_roles = roles(&["RootWebArea", "complementary"]);
            moved.container_text = Some("complementary|Trending".into());
            pairs.push(pair(
                Label::Different,
                "same_name_other_container",
                &t.page,
                t.base.clone(),
                moved,
            ));
        }
        // ---- different: same name, another role (hard gate) ------------------------------
        for t in g02.sample(&mut rng, 10) {
            let mut other = rerender(t, &mut rng, 1);
            other.role = if t.control.role == "link" {
                "button".into()
            } else {
                "link".into()
            };
            other.attributes.insert("role".into(), other.role.clone());
            pairs.push(pair(
                Label::Different,
                "different_role_same_name",
                &t.page,
                t.base.clone(),
                other,
            ));
        }
        // ---- different: same descriptor inside a frame (hard gate) -----------------------
        for t in g02.sample(&mut rng, 12).chain(likes.sample(&mut rng, 4)) {
            let mut framed = rerender(t, &mut rng, 1);
            framed.frame_lineage = vec![format!("iframe:/{}/embed:0", t.fixture)];
            pairs.push(pair(
                Label::Different,
                "different_frame_lineage",
                &t.page,
                t.base.clone(),
                framed,
            ));
        }
        // ---- different: a second "Open" link of the card pointing at another href template
        // (ids are unique per document, so the sibling anchor carries its own id or none) ----
        for t in opens.sample(&mut rng, 12) {
            let n = ordinal_of(&t.control.id);
            let mut other = rerender(t, &mut rng, 1);
            let (prefix, href) = match rng.random_range(0..3u8) {
                0 => ("edit", format!("/g06/item/{n}/edit")),
                1 => ("archive", format!("/g06/archive?id={n}")),
                _ => ("history", format!("/g06/item?id={n}&tab=history")),
            };
            other.href = Some(href.clone());
            other.attributes.insert("href".into(), href);
            if rng.random_bool(0.5) {
                other.attributes.insert("id".into(), format!("{prefix}-{n}"));
            } else {
                other.attributes.remove("id");
            }
            pairs.push(pair(
                Label::Different,
                "different_href_template",
                &t.page,
                t.base.clone(),
                other,
            ));
        }

        Some(Corpus {
            version: VERSION,
            seed: SEED,
            sources: SOURCES.iter().map(|s| (*s).to_owned()).collect(),
            pairs,
        })
    }
}
