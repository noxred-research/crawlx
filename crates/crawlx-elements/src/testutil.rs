//! Test fixtures: synthetic bundles and descriptors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, SessionId, TabId};
use crawlx_core::observation::{
    AxNode, BoundingBox, DomNodeSupplement, FrameInfo, ObservationBundle, ObservedDescriptor, RuntimeLocator,
};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};

pub fn page_url() -> url::Url {
    url::Url::parse("https://shop.example/list").unwrap()
}

pub fn locator(backend: i64) -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId("tab".into()),
        frame: FrameId("main".into()),
        backend_node_id: BackendNodeId(backend),
        object_id: None,
        ax_node_id: Some(AxNodeId(format!("ax{backend}"))),
        epoch: ObservationEpoch::default(),
    }
}

pub fn bbox(x: f64, y: f64, w: f64, h: f64) -> BoundingBox {
    BoundingBox {
        x,
        y,
        width: w,
        height: h,
    }
}

pub fn attrs(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// A bundle under construction.
pub struct Page {
    pub bundle: ObservationBundle,
}

impl Page {
    pub fn new() -> Self {
        let canonical = Canonicalizer::canonicalize(
            "https://shop.example/list",
            &page_url(),
            &CanonicalizeOptions::default(),
        )
        .unwrap();
        let mut bundle = ObservationBundle::empty(SessionId::new(), TabId("tab".into()), canonical);
        bundle.frames.push(FrameInfo {
            id: FrameId("main".into()),
            parent: None,
            url: "https://shop.example/list".into(),
            same_origin: true,
            lineage: Vec::new(),
        });
        Self { bundle }
    }

    /// Append an AX node (`ax{backend}`), linking it to its parent.
    pub fn ax(&mut self, backend: i64, parent: Option<i64>, role: &str, name: &str) -> &mut AxNode {
        let node = AxNode {
            locator: locator(backend),
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
        };
        if let Some(p) = parent {
            let me = AxNodeId(format!("ax{backend}"));
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

    pub fn dom(&mut self, backend: i64, tag: &str, kv: &[(&str, &str)]) -> &mut DomNodeSupplement {
        let d = DomNodeSupplement {
            tag: tag.to_owned(),
            attributes: attrs(kv),
            ..DomNodeSupplement::default()
        };
        self.bundle.dom_supplement.nodes.insert(backend, d);
        self.bundle.dom_supplement.nodes.get_mut(&backend).unwrap()
    }
}

/// A plain descriptor for `role`/`name` with a button-sized box.
pub fn descriptor(role: &str, name: &str) -> ObservedDescriptor {
    ObservedDescriptor {
        locator: locator(1),
        role: role.to_owned(),
        accessible_name: Some(name.to_owned()),
        description: None,
        tag: None,
        attributes: BTreeMap::new(),
        text: None,
        href: None,
        bbox: Some(bbox(10.0, 10.0, 100.0, 30.0)),
        frame_lineage: Vec::new(),
        ancestor_roles: Vec::new(),
        container_text: None,
        focusable: false,
        disabled: false,
        visible: true,
        listeners: Vec::new(),
        cursor: None,
        in_closed_shadow_root: false,
        instance_ordinal: 0,
    }
}

/// A product list: `main` > `list` > one `listitem` per title, each holding a
/// heading, `extra_wrappers` generic wrappers and an "Add to cart (counter)" button.
pub fn card_page(titles: &[&str], extra_wrappers: usize, counter: u32) -> Page {
    let mut p = Page::new();
    p.ax(1, None, "RootWebArea", "Shop");
    p.ax(2, Some(1), "main", "Shop");
    p.ax(3, Some(2), "list", "");
    for (idx, title) in titles.iter().enumerate() {
        let i = i32::try_from(idx).unwrap();
        let base = 100 * (i64::from(i) + 1);
        p.ax(base, Some(3), "listitem", "");
        p.ax(base + 50, Some(base), "heading", title);
        let mut parent = base;
        for w in 0..i64::try_from(extra_wrappers).unwrap() {
            let id = base + 1 + w;
            p.ax(id, Some(parent), "generic", "");
            parent = id;
        }
        let btn = base + 60;
        let node = p.ax(btn, Some(parent), "button", &format!("Add to cart ({counter})"));
        node.focusable = true;
        node.bbox = Some(bbox(20.0, 100.0 + 120.0 * f64::from(i), 120.0, 32.0));
        p.dom(btn, "button", &[("type", "button")]).bbox =
            Some(bbox(20.0, 100.0 + 120.0 * f64::from(i), 120.0, 32.0));
    }
    p
}
