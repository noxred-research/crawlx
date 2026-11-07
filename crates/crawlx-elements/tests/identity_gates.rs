//! Identity quality gates: identity stability over 500 synthetic re-renders (counters in
//! names, wrapper-depth changes, card and section reordering, varying card counts) with
//! collision <= 0.5% and split <= 2%, and cross-session identity agreement >= 99%.
//!
//! A "logical control" is what `ElementIdentityV1` is defined over: a control template.
//! Repeated cards inside one named section share one identity and are told apart by
//! `instance_ordinal`, so the per-section "Add to cart" and "Details" templates
//! count once each; every other control is unique.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, SessionId, TabId};
use crawlx_core::observation::{
    AxNode, BoundingBox, DomNodeSupplement, FrameInfo, ObservationBundle, RuntimeLocator,
};
use crawlx_core::ElementIdentityHash;
use crawlx_elements::{
    rates, CandidateDiscovery, DiscoveryConfig, IdentityBuilder, IdentityResolver, InMemoryIdentityIndex,
    MatchDecision, MatchWeights,
};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::{BTreeMap, BTreeSet};

const RERENDERS: usize = 500;
const NAV: &[(&str, &str)] = &[
    ("Home", "/"),
    ("Orders", "/orders"),
    ("Account", "/account/42"),
    ("Help", "/help"),
];
const SECTIONS: &[&str] = &["Featured", "Clearance", "New arrivals"];
const FOOTER: &[(&str, &str)] = &[("Privacy", "/privacy"), ("Terms", "/terms")];

/// Stable id ranges: nav 10.., toolbar 20.., footer 30.., load-more 40, sections 1000·(s+1),
/// cards 1000·(s+1) + 100·(card+1), button +60, details link +70.
const TOOLBAR: i64 = 20;
const FOOTER_BASE: i64 = 30;
const LOAD_MORE: i64 = 40;

/// Logical control labels.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Logical {
    Nav(usize),
    Search,
    InStock,
    OnSale,
    Apply,
    Clear,
    Footer(usize),
    Subscribe,
    LoadMore,
    Cart(usize),
    Details(usize),
}

const LOGICAL_COUNT: usize = NAV.len() + 5 + FOOTER.len() + 2 + 2 * SECTIONS.len();

/// A session's view of the shop: ids are offset per session so nothing runtime-bound is shared.
struct Session {
    id: SessionId,
    tab: &'static str,
    id_offset: i64,
}

fn locator(s: &Session, backend: i64) -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId(s.tab.into()),
        frame: FrameId("main".into()),
        backend_node_id: BackendNodeId(backend + s.id_offset),
        object_id: None,
        ax_node_id: Some(AxNodeId(format!("{}-ax{backend}", s.tab))),
        epoch: ObservationEpoch::default(),
    }
}

fn bbox(x: f64, y: f64) -> BoundingBox {
    BoundingBox {
        x,
        y,
        width: 120.0,
        height: 32.0,
    }
}

struct Page<'s> {
    session: &'s Session,
    bundle: ObservationBundle,
    y: f64,
}

impl<'s> Page<'s> {
    fn new(session: &'s Session) -> Self {
        let base = url::Url::parse("https://shop.example/list").unwrap();
        let canonical = Canonicalizer::canonicalize(
            "https://shop.example/list",
            &base,
            &CanonicalizeOptions::default(),
        )
        .unwrap();
        let mut bundle = ObservationBundle::empty(session.id, TabId(session.tab.into()), canonical);
        bundle.frames.push(FrameInfo {
            id: FrameId("main".into()),
            parent: None,
            url: "https://shop.example/list".into(),
            same_origin: true,
            lineage: Vec::new(),
        });
        Self {
            session,
            bundle,
            y: 0.0,
        }
    }

    fn ax(&mut self, backend: i64, parent: Option<i64>, role: &str, name: &str) -> &mut AxNode {
        let me = AxNodeId(format!("{}-ax{backend}", self.session.tab));
        let node = AxNode {
            locator: locator(self.session, backend),
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
            parent: parent.map(|p| AxNodeId(format!("{}-ax{p}", self.session.tab))),
            children: Vec::new(),
            bbox: None,
        };
        if let Some(p) = parent {
            let p = p + self.session.id_offset;
            if let Some(pn) = self
                .bundle
                .ax
                .nodes
                .iter_mut()
                .find(|n| n.locator.backend_node_id.0 == p)
            {
                pn.children.push(me);
            }
        }
        self.bundle.ax.nodes.push(node);
        self.bundle.ax.nodes.last_mut().unwrap()
    }

    /// A focusable control with a DOM supplement, laid out top to bottom.
    fn control(&mut self, backend: i64, parent: i64, role: &str, name: &str, tag: &str, kv: &[(&str, &str)]) {
        self.y += 40.0;
        let b = bbox(20.0, self.y);
        let node = self.ax(backend, Some(parent), role, name);
        node.focusable = true;
        node.bbox = Some(b);
        let d = DomNodeSupplement {
            tag: tag.to_owned(),
            attributes: kv
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            bbox: Some(b),
            ..DomNodeSupplement::default()
        };
        self.bundle
            .dom_supplement
            .nodes
            .insert(backend + self.session.id_offset, d);
    }
}

/// Logical label of a control, recovered from its (session-independent) backend id.
fn logical_of(backend: i64, session: &Session) -> Logical {
    let b = backend - session.id_offset;
    if b >= 1_000 {
        let section = usize::try_from(b / 1_000 - 1).unwrap();
        return match b % 100 {
            60 => Logical::Cart(section),
            70 => Logical::Details(section),
            other => panic!("unexpected card control id {b} ({other})"),
        };
    }
    match b {
        10..=19 => Logical::Nav(usize::try_from(b - 10).unwrap()),
        20 => Logical::Search,
        21 => Logical::InStock,
        22 => Logical::OnSale,
        23 => Logical::Apply,
        24 => Logical::Clear,
        30..=31 => Logical::Footer(usize::try_from(b - FOOTER_BASE).unwrap()),
        32 => Logical::Subscribe,
        40 => Logical::LoadMore,
        other => panic!("unexpected control id {other}"),
    }
}

/// Render `r` of the shop.
///
/// Perturbations per render: cart/load-more counters, `r % 4` extra wrappers between card
/// and button, card order rotated (reversed on odd renders), section order rotated, 2–5
/// cards per section, nav before or after `main`, a live status line, a `data-render`
/// attribute, and card titles that differ per render (static text, not a heading).
fn render(session: &Session, r: usize) -> ObservationBundle {
    let mut p = Page::new(session);
    p.ax(1, None, "RootWebArea", "Shop");
    let nav = |p: &mut Page<'_>| {
        p.ax(5, Some(1), "navigation", "");
        for (i, (name, href)) in NAV.iter().enumerate() {
            p.control(
                10 + i64::try_from(i).unwrap(),
                5,
                "link",
                name,
                "a",
                &[("href", href)],
            );
        }
    };
    let nav_first = r % 3 != 2;
    if nav_first {
        nav(&mut p);
    }
    p.ax(2, Some(1), "main", "Shop");
    p.ax(4, Some(2), "status", &format!("Updated {} s ago", r * 7 % 60));
    // Toolbar: a named landmark region holding the filter controls.
    p.ax(6, Some(2), "region", "Filters");
    p.control(
        TOOLBAR,
        6,
        "textbox",
        "Search products",
        "input",
        &[("type", "search"), ("name", "q")],
    );
    p.control(
        TOOLBAR + 1,
        6,
        "checkbox",
        "In stock only",
        "input",
        &[("type", "checkbox"), ("name", "stock")],
    );
    p.control(
        TOOLBAR + 2,
        6,
        "checkbox",
        "On sale",
        "input",
        &[("type", "checkbox"), ("name", "sale")],
    );
    p.control(
        TOOLBAR + 3,
        6,
        "button",
        "Apply filters",
        "button",
        &[("type", "button")],
    );
    p.control(
        TOOLBAR + 4,
        6,
        "button",
        "Clear filters",
        "button",
        &[("type", "button")],
    );

    let mut sections: Vec<usize> = (0..SECTIONS.len()).collect();
    sections.rotate_left(r % SECTIONS.len());
    for &s in &sections {
        let sbase = 1_000 * (i64::try_from(s).unwrap() + 1);
        p.ax(sbase, Some(2), "region", SECTIONS[s]);
        p.ax(sbase + 1, Some(sbase), "list", "");
        let cards = 2 + (r + s) % 4;
        let mut order: Vec<usize> = (0..cards).collect();
        order.rotate_left(r % cards);
        if r % 2 == 1 {
            order.reverse();
        }
        for &card in &order {
            let cbase = sbase + 100 * (i64::try_from(card).unwrap() + 1);
            p.ax(cbase, Some(sbase + 1), "listitem", "");
            p.ax(
                cbase + 50,
                Some(cbase),
                "StaticText",
                &format!("Item {card} of render {r}"),
            );
            let mut parent = cbase;
            for w in 0..i64::try_from(r % 4).unwrap() {
                let id = cbase + 1 + w;
                p.ax(id, Some(parent), "generic", "");
                parent = id;
            }
            p.control(
                cbase + 60,
                parent,
                "button",
                &format!("Add to cart ({r})"),
                "button",
                &[("type", "button"), ("data-render", &r.to_string())],
            );
            let href = format!("/items/{}?ref=list{r}", 7_000 + s * 100 + card);
            p.control(cbase + 70, parent, "link", "Details", "a", &[("href", &href)]);
        }
    }
    p.control(
        LOAD_MORE,
        2,
        "button",
        &format!("Load more ({} left)", 97 - r % 50),
        "button",
        &[("type", "button")],
    );
    p.ax(7, Some(1), "contentinfo", "");
    for (i, (name, href)) in FOOTER.iter().enumerate() {
        p.control(
            FOOTER_BASE + i64::try_from(i).unwrap(),
            7,
            "link",
            name,
            "a",
            &[("href", href)],
        );
    }
    p.control(
        FOOTER_BASE + 2,
        7,
        "button",
        "Subscribe",
        "button",
        &[("type", "submit")],
    );
    if !nav_first {
        nav(&mut p);
    }
    p.bundle
}

/// `(logical label, hash)` for every discovered control of a render.
fn hashes(bundle: &ObservationBundle, session: &Session) -> Vec<(Logical, ElementIdentityHash)> {
    let base = bundle.url.url.clone();
    CandidateDiscovery::discover(bundle, &DiscoveryConfig::default())
        .iter()
        .map(|c| {
            let dest =
                IdentityBuilder::destination_key(&c.descriptor, &base, &CanonicalizeOptions::default());
            let hash = IdentityBuilder::hash(&IdentityBuilder::build(&c.descriptor, dest)).unwrap();
            (logical_of(c.descriptor.locator.backend_node_id.0, session), hash)
        })
        .collect()
}

fn session_a() -> Session {
    Session {
        id: SessionId::new(),
        tab: "tab-a",
        id_offset: 0,
    }
}

#[test]
fn five_hundred_rerenders_keep_collision_and_split_under_the_adr_gates() {
    let session = session_a();
    let mut truth: Vec<(ElementIdentityHash, Logical)> = Vec::with_capacity(RERENDERS * 40);
    for r in 0..RERENDERS {
        let bundle = render(&session, r);
        let hs = hashes(&bundle, &session);
        let distinct: BTreeSet<Logical> = hs.iter().map(|(l, _)| *l).collect();
        assert_eq!(
            distinct.len(),
            LOGICAL_COUNT,
            "render {r} exposes every logical control"
        );
        truth.extend(hs.into_iter().map(|(l, h)| (h, l)));
    }
    let (collision, split) = rates(&truth);
    assert!(
        collision <= 0.005,
        "collision rate {collision} > 0.5% (identity gate)"
    );
    assert!(split <= 0.02, "split rate {split} > 2% (identity gate)");
}

#[test]
fn the_weighted_matcher_reuses_every_identity_after_the_first_render() {
    let session = session_a();
    let resolver = IdentityResolver::with_destination(
        url::Url::parse("https://shop.example/list").unwrap(),
        CanonicalizeOptions::default(),
    );
    let mut index = InMemoryIdentityIndex::new();
    let mut minted_after_first = 0usize;
    let mut resolutions = 0usize;
    for r in 0..RERENDERS {
        let bundle = render(&session, r);
        for c in CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default()) {
            let resolved = resolver
                .resolve(&c.descriptor, &index, &MatchWeights::default())
                .unwrap();
            if r > 0 {
                resolutions += 1;
                if matches!(resolved.decision, MatchDecision::MintedNew { .. }) {
                    minted_after_first += 1;
                }
            }
            index.record(&resolved);
        }
    }
    assert_eq!(
        index.len(),
        LOGICAL_COUNT,
        "one known identity per logical control"
    );
    let split = minted_after_first as f64 / resolutions as f64;
    assert!(
        split <= 0.02,
        "matcher minted {minted_after_first} of {resolutions} ({split}) > 2%"
    );
}

#[test]
fn identities_agree_across_sessions_for_at_least_99_percent_of_controls() {
    let a = session_a();
    let b = Session {
        id: SessionId::new(),
        tab: "tab-b",
        id_offset: 50_000,
    };
    let mut agree = 0usize;
    let mut total = 0usize;
    for r in 0..20 {
        // Session B sees a different render (counters, wrappers, order, card count) of the same app.
        let ha: BTreeMap<Logical, ElementIdentityHash> = hashes(&render(&a, r), &a).into_iter().collect();
        let hb: BTreeMap<Logical, ElementIdentityHash> = hashes(&render(&b, r + 7), &b).into_iter().collect();
        assert_eq!(ha.len(), LOGICAL_COUNT);
        for (logical, h) in &ha {
            total += 1;
            if hb.get(logical) == Some(h) {
                agree += 1;
            }
        }
    }
    let agreement = agree as f64 / total as f64;
    assert!(
        agreement >= 0.99,
        "cross-session agreement {agreement} < 99% (identity gate)"
    );
}

#[test]
fn real_changes_still_move_the_hash_under_the_same_gates() {
    // Guard against a vacuous gate: renaming a section (a real container change) must produce
    // new hashes for its two templates and leave every other control alone.
    let session = session_a();
    let before: BTreeMap<Logical, ElementIdentityHash> =
        hashes(&render(&session, 3), &session).into_iter().collect();
    let mut bundle = render(&session, 3);
    let region = bundle
        .ax
        .nodes
        .iter_mut()
        .find(|n| n.role == "region" && n.name.as_deref() == Some("Clearance"))
        .unwrap();
    region.name = Some("Bargain bin".to_owned());
    let after: BTreeMap<Logical, ElementIdentityHash> = hashes(&bundle, &session).into_iter().collect();
    let clearance = SECTIONS.iter().position(|s| *s == "Clearance").unwrap();
    assert_ne!(
        before[&Logical::Cart(clearance)],
        after[&Logical::Cart(clearance)]
    );
    assert_ne!(
        before[&Logical::Details(clearance)],
        after[&Logical::Details(clearance)]
    );
    for (l, h) in &before {
        if !matches!(l, Logical::Cart(s) | Logical::Details(s) if *s == clearance) {
            assert_eq!(after[l], *h, "control {l:?} changed without a real difference");
        }
    }
}
