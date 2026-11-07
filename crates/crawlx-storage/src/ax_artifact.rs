//! Persistable projection of an [`ObservationBundle`].
//!
//! A state's fingerprint is reproducible only if the artifact stored with it carries every
//! input of `crawlx_state::Fingerprinter` and `MaskBuilder`: the AX nodes with their
//! parent/child links (node keys are role + sibling-ordinal paths), the DOM supplement
//! (listeners decide which generic nodes are widgets), the frame tree, the canonical URL and
//! the network operations of the epoch. `RuntimeLocator` itself is never persisted; only the
//! ids needed to rebuild the tree (AX node ids, backend node ids, frame ids) are kept, and
//! they are meaningless outside the reload.

use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{
    AxNode, AxSnapshot, BoundingBox, DomNodeSupplement, DomSupplement, FrameInfo, NetworkEpochSummary,
    ObservationBundle, RuntimeLocator,
};
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{AxNodeId, BackendNodeId, FrameId, SessionId, StoreError, TabId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Artifact kind under which the AX projection is stored with a state (`NewState::artifacts`).
pub const AX_ARTIFACT_KIND: &str = "ax_tree";
/// Artifact kind under which a state's `MaskSet` is stored.
pub const MASKS_ARTIFACT_KIND: &str = "masks";
/// Content type of both artifacts.
pub const ARTIFACT_CONTENT_TYPE: &str = "application/json";
/// Current `AxArtifact::version`.
pub const AX_ARTIFACT_VERSION: u16 = 1;

/// One frame of the observed tab.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct FrameArtifact {
    /// Frame id as the browser reported it.
    pub id: String,
    /// Parent frame id; `None` for the main frame.
    pub parent: Option<String>,
    /// Document URL of the frame, uncanonicalized.
    pub url: String,
    /// `true` when the frame shares its origin with the main frame.
    pub same_origin: bool,
    /// Digest-based lineage used by element identity.
    pub lineage: Vec<String>,
}

/// One AX node with the links the tree is rebuilt from.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct AxNodeArtifact {
    /// Frame that contains the node.
    pub frame: String,
    /// CDP backend node id; joins the node to `dom_supplement`.
    pub backend_node_id: i64,
    /// AX node id; `None` when the node has no AX counterpart.
    pub ax_node_id: Option<String>,
    /// ARIA role.
    pub role: String,
    /// Accessible name.
    pub name: Option<String>,
    /// Accessible description.
    pub description: Option<String>,
    /// Accessible value.
    pub value: Option<String>,
    /// Ignored for assistive technology.
    pub ignored: bool,
    /// Can receive keyboard focus.
    pub focusable: bool,
    /// Disabled.
    pub disabled: bool,
    /// `aria-expanded` state.
    pub expanded: Option<bool>,
    /// Checked state.
    pub checked: Option<String>,
    /// Remaining AX properties in sorted key order.
    pub properties: BTreeMap<String, String>,
    /// Parent AX node id.
    pub parent: Option<String>,
    /// Child AX node ids in document order.
    pub children: Vec<String>,
    /// Bounding box in CSS pixels.
    pub bbox: Option<BoundingBox>,
}

/// DOM evidence of one escalated node.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct DomNodeArtifact {
    /// Lower-case tag name.
    pub tag: String,
    /// HTML attributes in sorted key order.
    pub attributes: BTreeMap<String, String>,
    /// Computed CSS `cursor`.
    pub cursor: Option<String>,
    /// Event listener names.
    pub listeners: Vec<String>,
    /// Visible text content.
    pub text: Option<String>,
    /// Bounding box in CSS pixels.
    pub bbox: Option<BoundingBox>,
    /// Inside a shadow root.
    pub in_shadow_root: bool,
    /// That shadow root is closed.
    pub shadow_root_closed: bool,
}

/// Everything a signature and its masks derive from, in a stable JSON shape.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct AxArtifact {
    /// [`AX_ARTIFACT_VERSION`] when written.
    pub version: u16,
    /// Canonical URL of the main document.
    pub url: CanonicalUrl,
    /// Observation epoch of the capture.
    pub epoch: ObservationEpoch,
    /// Document title.
    pub title: Option<String>,
    /// Frames, main frame first.
    pub frames: Vec<FrameArtifact>,
    /// AX nodes in snapshot order.
    pub nodes: Vec<AxNodeArtifact>,
    /// DOM supplement keyed by backend node id.
    pub dom_supplement: BTreeMap<i64, DomNodeArtifact>,
    /// Backend node ids of generic elements found by listener inspection.
    pub listener_candidates: Vec<i64>,
    /// Network activity of the observation's epoch (the operations enter the signature).
    pub network: NetworkEpochSummary,
}

impl AxArtifact {
    /// Project `bundle`.
    #[must_use]
    pub fn from_bundle(bundle: &ObservationBundle) -> Self {
        Self {
            version: AX_ARTIFACT_VERSION,
            url: bundle.url.clone(),
            epoch: bundle.epoch,
            title: bundle.title.clone(),
            frames: bundle
                .frames
                .iter()
                .map(|f| FrameArtifact {
                    id: f.id.0.clone(),
                    parent: f.parent.as_ref().map(|p| p.0.clone()),
                    url: f.url.clone(),
                    same_origin: f.same_origin,
                    lineage: f.lineage.clone(),
                })
                .collect(),
            nodes: bundle
                .ax
                .nodes
                .iter()
                .map(|n| AxNodeArtifact {
                    frame: n.locator.frame.0.clone(),
                    backend_node_id: n.locator.backend_node_id.0,
                    ax_node_id: n.locator.ax_node_id.as_ref().map(|a| a.0.clone()),
                    role: n.role.clone(),
                    name: n.name.clone(),
                    description: n.description.clone(),
                    value: n.value.clone(),
                    ignored: n.ignored,
                    focusable: n.focusable,
                    disabled: n.disabled,
                    expanded: n.expanded,
                    checked: n.checked.clone(),
                    properties: n.properties.clone(),
                    parent: n.parent.as_ref().map(|p| p.0.clone()),
                    children: n.children.iter().map(|c| c.0.clone()).collect(),
                    bbox: n.bbox,
                })
                .collect(),
            dom_supplement: bundle
                .dom_supplement
                .nodes
                .iter()
                .map(|(id, s)| {
                    (
                        *id,
                        DomNodeArtifact {
                            tag: s.tag.clone(),
                            attributes: s.attributes.clone(),
                            cursor: s.cursor.clone(),
                            listeners: s.listeners.clone(),
                            text: s.text.clone(),
                            bbox: s.bbox,
                            in_shadow_root: s.in_shadow_root,
                            shadow_root_closed: s.shadow_root_closed,
                        },
                    )
                })
                .collect(),
            listener_candidates: bundle
                .dom_supplement
                .listener_candidates
                .iter()
                .map(|b| b.0)
                .collect(),
            network: bundle.network.clone(),
        }
    }

    /// Rebuild a bundle equivalent for fingerprinting and masking under `session`/`tab`.
    /// Runtime handles (`object_id`) are not restored; raw blobs and screenshots are absent.
    #[must_use]
    pub fn to_bundle(&self, session: SessionId, tab: TabId) -> ObservationBundle {
        let mut bundle = ObservationBundle::empty(session, tab.clone(), self.url.clone());
        bundle.epoch = self.epoch;
        bundle.title.clone_from(&self.title);
        bundle.frames = self
            .frames
            .iter()
            .map(|f| FrameInfo {
                id: FrameId(f.id.clone()),
                parent: f.parent.clone().map(FrameId),
                url: f.url.clone(),
                same_origin: f.same_origin,
                lineage: f.lineage.clone(),
            })
            .collect();
        bundle.ax = AxSnapshot {
            nodes: self
                .nodes
                .iter()
                .map(|n| AxNode {
                    locator: RuntimeLocator {
                        tab: tab.clone(),
                        frame: FrameId(n.frame.clone()),
                        backend_node_id: BackendNodeId(n.backend_node_id),
                        object_id: None,
                        ax_node_id: n.ax_node_id.clone().map(AxNodeId),
                        epoch: self.epoch,
                    },
                    role: n.role.clone(),
                    name: n.name.clone(),
                    description: n.description.clone(),
                    value: n.value.clone(),
                    ignored: n.ignored,
                    focusable: n.focusable,
                    disabled: n.disabled,
                    expanded: n.expanded,
                    checked: n.checked.clone(),
                    properties: n.properties.clone(),
                    parent: n.parent.clone().map(AxNodeId),
                    children: n.children.iter().cloned().map(AxNodeId).collect(),
                    bbox: n.bbox,
                })
                .collect(),
        };
        bundle.dom_supplement = DomSupplement {
            nodes: self
                .dom_supplement
                .iter()
                .map(|(id, s)| {
                    (
                        *id,
                        DomNodeSupplement {
                            tag: s.tag.clone(),
                            attributes: s.attributes.clone(),
                            cursor: s.cursor.clone(),
                            listeners: s.listeners.clone(),
                            text: s.text.clone(),
                            bbox: s.bbox,
                            in_shadow_root: s.in_shadow_root,
                            shadow_root_closed: s.shadow_root_closed,
                        },
                    )
                })
                .collect(),
            listener_candidates: self
                .listener_candidates
                .iter()
                .copied()
                .map(BackendNodeId)
                .collect(),
        };
        bundle.network = self.network.clone();
        bundle
    }

    /// JSON bytes to store through `ArtifactStore::put`.
    ///
    /// # Errors
    /// `StoreError::Serialization` when encoding fails.
    pub fn to_json(&self) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(self).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    /// Decode bytes written by [`Self::to_json`].
    ///
    /// # Errors
    /// `StoreError::Serialization` when the bytes are not a valid artifact or carry an
    /// unsupported version.
    pub fn from_json(bytes: &[u8]) -> Result<Self, StoreError> {
        let artifact: Self =
            serde_json::from_slice(bytes).map_err(|e| StoreError::Serialization(e.to_string()))?;
        if artifact.version != AX_ARTIFACT_VERSION {
            return Err(StoreError::Serialization(format!(
                "unsupported ax artifact version {}",
                artifact.version
            )));
        }
        Ok(artifact)
    }
}
