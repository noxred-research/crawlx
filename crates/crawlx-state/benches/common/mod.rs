//! Synthetic AX-tree builder shared by the `crawlx-state` benches (mirrors the crate's
//! private `testutil::Page`).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::hash::Digest;
use crawlx_core::observation::{AxNode, ObservationBundle, RuntimeLocator};
use crawlx_core::url::{CanonicalUrl, RouteTemplate};
use crawlx_core::{
    AxNodeId, BackendNodeId, FrameId, ObservationEpoch, SessionId, StateClusterId, StateId, TabId,
};
use std::collections::BTreeMap;

pub fn state_id(n: u128) -> StateId {
    StateId(uuid::Uuid::from_u128(n))
}

pub fn cluster_ids() -> impl FnMut() -> StateClusterId + Send + 'static {
    let mut n = 0u128;
    move || {
        n += 1;
        StateClusterId(uuid::Uuid::from_u128(n))
    }
}

/// Incremental AX tree builder; node `i` gets id `n{i}`.
#[derive(Default, Clone)]
pub struct Page {
    pub nodes: Vec<AxNode>,
}

impl Page {
    pub fn add(&mut self, parent: Option<usize>, role: &str, name: &str) -> usize {
        let idx = self.nodes.len();
        let locator = RuntimeLocator {
            tab: TabId("t".into()),
            frame: FrameId("f".into()),
            backend_node_id: BackendNodeId(i64::try_from(idx).unwrap() + 1),
            object_id: None,
            ax_node_id: Some(AxNodeId(format!("n{idx}"))),
            epoch: ObservationEpoch::default(),
        };
        self.nodes.push(AxNode {
            locator,
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
            parent: parent.map(|p| AxNodeId(format!("n{p}"))),
            children: Vec::new(),
            bbox: None,
        });
        if let Some(p) = parent {
            self.nodes[p].children.push(AxNodeId(format!("n{idx}")));
        }
        idx
    }

    pub fn bundle(&self, path: &str) -> ObservationBundle {
        let url = CanonicalUrl {
            url: url::Url::parse(&format!("https://shop.test{path}")).unwrap(),
            key: Digest::of("t", path.as_bytes()),
            origin: "https://shop.test".to_owned(),
            route_template: RouteTemplate(path.to_owned()),
            params: Vec::new(),
        };
        let mut b = ObservationBundle::empty(SessionId::new(), TabId("t".into()), url);
        b.ax.nodes = self.nodes.clone();
        b
    }
}

/// A page with `target` nodes: sections of 100 nodes mixing links, buttons and text.
/// `variant` perturbs names so distinct pages look like distinct-but-similar states.
pub fn big_page(target: usize, variant: usize) -> Page {
    let mut p = Page::default();
    let root = p.add(None, "RootWebArea", "Big");
    let mut count = 1;
    let mut section = 0;
    while count < target {
        let sec = p.add(Some(root), "region", &format!("Section {section}"));
        count += 1;
        for i in 0..99 {
            let (role, name) = match i % 4 {
                0 => ("link", format!("Item link {}", (i + variant) % 13)),
                1 => ("button", format!("Action {}", (i + variant) % 7)),
                2 => ("paragraph", format!("Body text number {i} v{variant}")),
                _ => ("StaticText", format!("Label {i}")),
            };
            p.add(Some(sec), role, &name);
            count += 1;
        }
        section += 1;
    }
    p
}
