//! Criterion benches for the element plane: `identity_hash`
//! (1,000 descriptors → `ElementIdentityV1` → BLAKE3 hash), `identity_weighted_match_1k`
//! (1,000 re-rendered descriptors resolved against an index of 1,000 known identities)
//! and `candidate_ladder_ax_10k` (the discovery ladder over a 10k-node AX tree).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, SessionId, TabId};
use crawlx_core::observation::{
    AxNode, BoundingBox, DomNodeSupplement, FrameInfo, ObservationBundle, ObservedDescriptor, RuntimeLocator,
};
use crawlx_elements::{
    CandidateDiscovery, DiscoveryConfig, IdentityBuilder, IdentityResolver, InMemoryIdentityIndex,
    MatchDecision, MatchWeights,
};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::BTreeMap;
use uuid::Uuid;

const ORIGIN: &str = "https://shop.example";
const CONTROLS: usize = 1_000;
const AX_NODES: usize = 10_000;

/// Letters for index `i` ("a", "b", ... "z", "ba", ...): identity names strip digits, so
/// names must differ by letters to produce distinct identities.
fn letters(mut i: usize) -> String {
    let mut s = String::new();
    loop {
        s.insert(0, char::from(b'a' + u8::try_from(i % 26).unwrap()));
        i /= 26;
        if i == 0 {
            return s;
        }
    }
}

fn locator(backend: i64) -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId("tab".into()),
        frame: FrameId("main".into()),
        backend_node_id: BackendNodeId(backend),
        object_id: None,
        ax_node_id: Some(AxNodeId(format!("ax{backend}"))),
        epoch: ObservationEpoch::default(),
    }
}

fn ax(id: i64, parent: Option<i64>, role: &str, name: &str) -> AxNode {
    AxNode {
        locator: locator(id),
        role: role.to_owned(),
        name: (!name.is_empty()).then(|| name.to_owned()),
        description: None,
        value: None,
        ignored: false,
        focusable: false,
        disabled: false,
        expanded: None,
        checked: None,
        properties: BTreeMap::new(),
        parent: parent.map(|p| AxNodeId(format!("ax{p}"))),
        children: Vec::new(),
        bbox: None,
    }
}

fn bbox(i: usize) -> BoundingBox {
    BoundingBox {
        x: 20.0 + 160.0 * ((i % 4) as f64),
        y: 100.0 + 40.0 * ((i / 4) as f64),
        width: 120.0,
        height: 32.0,
    }
}

fn empty_bundle() -> ObservationBundle {
    let base = url::Url::parse(ORIGIN).unwrap();
    let canonical =
        Canonicalizer::canonicalize(&format!("{ORIGIN}/list"), &base, &CanonicalizeOptions::default())
            .unwrap();
    let mut b = ObservationBundle::empty(SessionId(Uuid::from_u128(7)), TabId("tab".into()), canonical);
    b.frames.push(FrameInfo {
        id: FrameId("main".into()),
        parent: None,
        url: format!("{ORIGIN}/list"),
        same_origin: true,
        lineage: Vec::new(),
    });
    b
}

/// Section landmark → list → `cards` list items, each holding a button and a link:
/// a catalogue page with `n` distinct controls (each carries a durable `data-testid`).
/// On `render > 0` the page re-renders like a real one: wording of the labels, counters,
/// wrapper depth and card order change while durable attributes, hrefs and layout stay.
fn catalogue(n: usize, render: usize) -> ObservationBundle {
    let mut b = empty_bundle();
    let mut nodes: Vec<AxNode> = vec![ax(1, None, "RootWebArea", "Shop"), ax(2, Some(1), "main", "Shop")];
    let sections = n.div_ceil(50);
    let mut next_id: i64 = 100;
    let alloc = |next: &mut i64| {
        let id = *next;
        *next += 1;
        id
    };
    let mut control_index = 0usize;
    for s in 0..sections {
        let section = alloc(&mut next_id);
        nodes.push(ax(section, Some(2), "region", &format!("Section {}", letters(s))));
        let list = alloc(&mut next_id);
        nodes.push(ax(list, Some(section), "list", ""));
        let mut cards: Vec<usize> = (0..25).collect();
        cards.rotate_left(render % 25);
        for card in cards {
            if control_index >= n {
                break;
            }
            let item = alloc(&mut next_id);
            nodes.push(ax(item, Some(list), "listitem", ""));
            let mut parent = item;
            for _ in 0..(render % 3) {
                let wrapper = alloc(&mut next_id);
                nodes.push(ax(wrapper, Some(parent), "generic", ""));
                parent = wrapper;
            }
            for kind in 0..2 {
                if control_index >= n {
                    break;
                }
                let id = alloc(&mut next_id);
                let logical = s * 50 + card * 2 + kind;
                let name = letters(logical / 2);
                let (role, tag, label, attrs): (&str, &str, String, Vec<(String, String)>) = if kind == 0 {
                    (
                        "button",
                        "button",
                        if render == 0 {
                            format!("Add {name} to cart ({render})")
                        } else {
                            format!("Put {name} in basket ({render})")
                        },
                        vec![
                            ("type".into(), "button".into()),
                            ("data-testid".into(), format!("add-{name}")),
                            ("data-render".into(), render.to_string()),
                        ],
                    )
                } else {
                    (
                        "link",
                        "a",
                        if render == 0 {
                            format!("Details {name}")
                        } else {
                            format!("View {name}")
                        },
                        vec![
                            ("href".into(), format!("/items/{}", 7_000 + s * 100 + card)),
                            ("data-testid".into(), format!("details-{name}")),
                        ],
                    )
                };
                let mut node = ax(id, Some(parent), role, &label);
                node.focusable = true;
                let bb = bbox(logical);
                node.bbox = Some(bb);
                nodes.push(node);
                b.dom_supplement.nodes.insert(
                    id,
                    DomNodeSupplement {
                        tag: tag.to_owned(),
                        attributes: attrs.into_iter().collect(),
                        bbox: Some(bb),
                        ..DomNodeSupplement::default()
                    },
                );
                control_index += 1;
            }
        }
    }
    link_children(&mut nodes);
    b.ax.nodes = nodes;
    b
}

/// Fill every node's `children` from the `parent` links, in document order.
fn link_children(nodes: &mut [AxNode]) {
    let mut by_id: BTreeMap<String, usize> = BTreeMap::new();
    for (i, n) in nodes.iter().enumerate() {
        by_id.insert(n.locator.ax_node_id.clone().unwrap().0, i);
    }
    let edges: Vec<(usize, AxNodeId)> = nodes
        .iter()
        .filter_map(|n| {
            n.parent
                .as_ref()
                .and_then(|p| by_id.get(&p.0))
                .map(|&pi| (pi, n.locator.ax_node_id.clone().unwrap()))
        })
        .collect();
    for (pi, child) in edges {
        nodes[pi].children.push(child);
    }
}

/// A 10k-node AX tree shaped like a data-heavy page: nested groups and tables with
/// static text, every tenth node a widget, every fourth a focusable cell, some
/// listener-only generics in the DOM supplement.
fn wide_tree(n: usize) -> ObservationBundle {
    let mut b = empty_bundle();
    let mut nodes: Vec<AxNode> = vec![
        ax(1, None, "RootWebArea", "Dashboard"),
        ax(2, Some(1), "main", "Dashboard"),
    ];
    let mut id: i64 = 10;
    let mut group = 2;
    while nodes.len() < n {
        let i = nodes.len();
        if i % 40 == 2 {
            group = id;
            nodes.push(ax(
                group,
                Some(2),
                if i % 80 == 2 { "table" } else { "group" },
                &format!("Block {}", letters(i / 40)),
            ));
            id += 1;
            continue;
        }
        let (role, name, widget) = match i % 10 {
            0 => ("button", format!("Action {}", letters(i)), true),
            1 => ("link", format!("Open {}", letters(i)), true),
            2 => ("checkbox", format!("Flag {}", letters(i)), true),
            3 => ("StaticText", format!("cell {i}"), false),
            4 => ("gridcell", format!("{i}"), false),
            5 => ("combobox", format!("Choose {}", letters(i)), true),
            6 => ("generic", String::new(), false),
            7 => ("row", String::new(), false),
            8 => ("StaticText", format!("label {i}"), false),
            _ => ("menuitem", format!("Menu {}", letters(i)), true),
        };
        let mut node = ax(id, Some(group), role, &name);
        node.focusable = widget || i.is_multiple_of(4);
        if i % 50 == 5 {
            node.expanded = Some(false);
        }
        let bb = bbox(i);
        node.bbox = Some(bb);
        nodes.push(node);
        let listener_only = !widget && i.is_multiple_of(6);
        if widget || listener_only {
            let (tag, attrs): (&str, Vec<(String, String)>) = match role {
                "button" => ("button", vec![("type".into(), "button".into())]),
                "link" => ("a", vec![("href".into(), format!("/rows/{i}"))]),
                "checkbox" => (
                    "input",
                    vec![
                        ("type".into(), "checkbox".into()),
                        ("name".into(), format!("f{i}")),
                    ],
                ),
                "combobox" => ("select", vec![("name".into(), format!("sel{i}"))]),
                "menuitem" => ("div", vec![("role".into(), "menuitem".into())]),
                _ => ("div", vec![("tabindex".into(), "0".into())]),
            };
            let mut d = DomNodeSupplement {
                tag: tag.to_owned(),
                attributes: attrs.into_iter().collect(),
                bbox: Some(bb),
                ..DomNodeSupplement::default()
            };
            if listener_only {
                d.listeners.push("click".to_owned());
                d.cursor = Some("pointer".to_owned());
                b.dom_supplement.listener_candidates.push(BackendNodeId(id));
            }
            b.dom_supplement.nodes.insert(id, d);
        }
        id += 1;
    }
    link_children(&mut nodes);
    b.ax.nodes = nodes;
    b
}

fn descriptors(bundle: &ObservationBundle) -> Vec<ObservedDescriptor> {
    CandidateDiscovery::discover(bundle, &DiscoveryConfig::default())
        .into_iter()
        .map(|c| c.descriptor)
        .collect()
}

fn identity_hash(c: &mut Criterion) {
    let base = url::Url::parse(&format!("{ORIGIN}/list")).unwrap();
    let descs = descriptors(&catalogue(CONTROLS, 0));
    assert_eq!(descs.len(), CONTROLS);
    let mut g = c.benchmark_group("identity_hash");
    g.throughput(Throughput::Elements(descs.len() as u64));
    g.bench_with_input(
        BenchmarkId::new("descriptors", descs.len()),
        &descs,
        |b, descs| {
            b.iter(|| {
                let mut acc = 0u8;
                for d in descs {
                    let dest = IdentityBuilder::destination_key(
                        black_box(d),
                        &base,
                        &CanonicalizeOptions::default(),
                    );
                    let hash = IdentityBuilder::hash(&IdentityBuilder::build(d, dest)).unwrap();
                    acc ^= hash.0 .0[0];
                }
                acc
            });
        },
    );
    g.finish();
}

fn identity_weighted_match_1k(c: &mut Criterion) {
    let resolver = IdentityResolver::with_destination(
        url::Url::parse(&format!("{ORIGIN}/list")).unwrap(),
        CanonicalizeOptions::default(),
    );
    let weights = MatchWeights::default();
    let mut index = InMemoryIdentityIndex::new();
    for d in descriptors(&catalogue(CONTROLS, 0)) {
        index.record(&resolver.resolve(&d, &index, &weights).unwrap());
    }
    assert_eq!(index.len(), CONTROLS, "one known identity per control");
    // Re-render 1: counters, wrapper depth and card order differ, so the exact-hash
    // shortcut misses on the buttons and the weighted scorer runs.
    let observed = descriptors(&catalogue(CONTROLS, 1));
    assert_eq!(observed.len(), CONTROLS);
    let minted = observed
        .iter()
        .filter(|d| {
            matches!(
                resolver.resolve(d, &index, &weights).unwrap().decision,
                MatchDecision::MintedNew { .. }
            )
        })
        .count();
    assert!(
        minted * 50 <= CONTROLS,
        "{minted} of {CONTROLS} re-rendered controls minted (> 2%)"
    );

    let mut g = c.benchmark_group("identity_weighted_match_1k");
    g.throughput(Throughput::Elements(observed.len() as u64));
    g.bench_with_input(
        BenchmarkId::new("resolve_against_index", observed.len()),
        &observed,
        |b, observed| {
            b.iter(|| {
                let mut reused = 0u32;
                for d in observed {
                    let r = resolver.resolve(black_box(d), &index, &weights).unwrap();
                    if matches!(r.decision, MatchDecision::Reused { .. }) {
                        reused += 1;
                    }
                }
                reused
            });
        },
    );
    g.finish();
}

fn candidate_ladder_ax_10k(c: &mut Criterion) {
    let bundle = wide_tree(AX_NODES);
    assert_eq!(bundle.ax.nodes.len(), AX_NODES);
    let config = DiscoveryConfig::default();
    let found = CandidateDiscovery::discover(&bundle, &config).len();
    assert!(found > 4_000, "{found} candidates over {AX_NODES} nodes");
    let mut g = c.benchmark_group("candidate_ladder_ax_10k");
    g.throughput(Throughput::Elements(AX_NODES as u64));
    g.bench_with_input(
        BenchmarkId::new("discover/nodes", AX_NODES),
        &bundle,
        |b, bundle| {
            b.iter(|| CandidateDiscovery::discover(black_box(bundle), &config).len());
        },
    );
    g.finish();
}

criterion_group!(
    benches,
    identity_hash,
    identity_weighted_match_1k,
    candidate_ladder_ax_10k
);
criterion_main!(benches);
