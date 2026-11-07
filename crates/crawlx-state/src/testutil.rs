//! Fixture builders shared by unit tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::hash::Digest;
use crawlx_core::observation::{AxNode, ObservationBundle};
use crawlx_core::url::{CanonicalUrl, RouteTemplate};
use crawlx_core::{AxNodeId, BackendNodeId, FrameId, ObservationEpoch, SessionId, StateId, TabId};
use std::collections::BTreeMap;

pub fn state_id(n: u128) -> StateId {
    StateId(uuid::Uuid::from_u128(n))
}

pub fn cluster_ids() -> impl FnMut() -> crawlx_core::StateClusterId + Send + 'static {
    let mut n = 0u128;
    move || {
        n += 1;
        crawlx_core::StateClusterId(uuid::Uuid::from_u128(n))
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
        let locator = crawlx_core::observation::RuntimeLocator {
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

    pub fn rename(&mut self, idx: usize, name: &str) {
        self.nodes[idx].name = Some(name.to_owned());
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

/// Indices of interesting nodes in [`orders_page`].
pub struct OrdersPage {
    pub page: Page,
    pub clock: usize,
    pub status: usize,
    pub paragraph: usize,
    pub main: usize,
    pub list: usize,
}

/// A realistic page: nav, search form, a short order list, a clock, a status line.
pub fn orders_page() -> OrdersPage {
    let mut p = Page::default();
    let root = p.add(None, "RootWebArea", "Orders");
    let banner = p.add(Some(root), "banner", "");
    let nav = p.add(Some(banner), "navigation", "Primary");
    for label in ["Home", "Products", "Cart", "Account"] {
        p.add(Some(nav), "link", label);
    }
    let clock = p.add(Some(banner), "timer", "Updated just now");
    let main = p.add(Some(root), "main", "");
    p.add(Some(main), "heading", "Your orders");
    let paragraph = p.add(Some(main), "paragraph", "Showing 3 orders");
    let form = p.add(Some(main), "form", "Search orders");
    p.add(Some(form), "textbox", "Search");
    p.add(Some(form), "button", "Search");
    let list = p.add(Some(main), "list", "Orders");
    for i in 0..8 {
        let li = p.add(Some(list), "listitem", "");
        p.add(Some(li), "link", "View order");
        p.add(Some(li), "StaticText", &format!("Order #{}", 1000 + i));
        p.add(Some(li), "button", "Reorder");
    }
    let status = p.add(Some(main), "status", "Saved");
    let footer = p.add(Some(root), "contentinfo", "");
    p.add(Some(footer), "link", "Help");
    p.add(Some(footer), "link", "Terms");
    OrdersPage {
        page: p,
        clock,
        status,
        paragraph,
        main,
        list,
    }
}
