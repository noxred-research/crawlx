//! Lookup structures over one `ObservationBundle`: AX parent chains, frames
//! and backend-id joins between the AX tree and the DOM supplement.

use std::collections::{BTreeMap, HashMap};

use crawlx_core::ids::{BackendNodeId, FrameId};
use crawlx_core::observation::{AxNode, FrameInfo, ObservationBundle, RuntimeLocator};

/// Guard against cyclic parent links in a malformed tree.
const MAX_CHAIN: usize = 64;

/// Read-only index over a bundle. Lookup maps are `HashMap`s but are never
/// iterated; ordered traversal goes through the bundle's own `Vec`s.
pub struct BundleIndex<'a> {
    bundle: &'a ObservationBundle,
    by_ax_id: HashMap<&'a str, usize>,
    /// First AX node per backend id, preferring non-ignored nodes.
    by_backend: BTreeMap<i64, usize>,
    frames: HashMap<&'a str, usize>,
}

impl<'a> BundleIndex<'a> {
    /// Index `bundle`: first AX node per AX id, first non-ignored AX node per
    /// backend id (falling back to the first node), and every frame by id.
    #[must_use]
    pub fn new(bundle: &'a ObservationBundle) -> Self {
        let mut by_ax_id = HashMap::with_capacity(bundle.ax.nodes.len());
        let mut by_backend: BTreeMap<i64, usize> = BTreeMap::new();
        for (i, n) in bundle.ax.nodes.iter().enumerate() {
            if let Some(id) = &n.locator.ax_node_id {
                by_ax_id.entry(id.0.as_str()).or_insert(i);
            }
            let key = n.locator.backend_node_id.0;
            match by_backend.get(&key) {
                Some(&prev) if !bundle.ax.nodes[prev].ignored || n.ignored => {}
                _ => {
                    by_backend.insert(key, i);
                }
            }
        }
        let frames = bundle
            .frames
            .iter()
            .enumerate()
            .map(|(i, f)| (f.id.0.as_str(), i))
            .collect();
        Self {
            bundle,
            by_ax_id,
            by_backend,
            frames,
        }
    }

    /// The bundle this index was built over.
    #[must_use]
    pub fn bundle(&self) -> &'a ObservationBundle {
        self.bundle
    }

    /// AX node for a backend node id.
    #[must_use]
    pub fn ax_by_backend(&self, id: i64) -> Option<&'a AxNode> {
        self.by_backend.get(&id).map(|&i| &self.bundle.ax.nodes[i])
    }

    /// Parent of `node`, if linked and present.
    #[must_use]
    pub fn parent(&self, node: &AxNode) -> Option<&'a AxNode> {
        let id = node.parent.as_ref()?;
        self.by_ax_id
            .get(id.0.as_str())
            .map(|&i| &self.bundle.ax.nodes[i])
    }

    /// Ancestors of `node`, innermost first.
    #[must_use]
    pub fn ancestors(&self, node: &AxNode) -> Vec<&'a AxNode> {
        let mut out = Vec::new();
        let mut cur = self.parent(node);
        while let Some(p) = cur {
            if out.len() >= MAX_CHAIN {
                break;
            }
            out.push(p);
            cur = self.parent(p);
        }
        out
    }

    /// Children of `node` that exist in the snapshot, in tree order.
    #[must_use]
    pub fn children(&self, node: &AxNode) -> Vec<&'a AxNode> {
        node.children
            .iter()
            .filter_map(|c| self.by_ax_id.get(c.0.as_str()))
            .map(|&i| &self.bundle.ax.nodes[i])
            .collect()
    }

    /// Frame with `id`, if the bundle lists it.
    #[must_use]
    pub fn frame(&self, id: &FrameId) -> Option<&'a FrameInfo> {
        self.frames.get(id.0.as_str()).map(|&i| &self.bundle.frames[i])
    }

    /// Frame lineage digests for `frame`; empty for the main or an unknown frame.
    #[must_use]
    pub fn lineage(&self, frame: &FrameId) -> Vec<String> {
        self.frame(frame).map(|f| f.lineage.clone()).unwrap_or_default()
    }

    /// The main frame: the first frame without a parent (or the first frame).
    #[must_use]
    pub fn main_frame(&self) -> Option<&'a FrameInfo> {
        self.bundle
            .frames
            .iter()
            .find(|f| f.parent.is_none())
            .or_else(|| self.bundle.frames.first())
    }

    /// Locator for a DOM-only node (no AX node): main frame, current epoch.
    #[must_use]
    pub fn dom_locator(&self, backend: i64) -> RuntimeLocator {
        RuntimeLocator {
            tab: self.bundle.tab.clone(),
            frame: self
                .main_frame()
                .map(|f| f.id.clone())
                .unwrap_or_else(|| FrameId(String::new())),
            backend_node_id: BackendNodeId(backend),
            object_id: None,
            ax_node_id: None,
            epoch: self.bundle.epoch,
        }
    }
}
