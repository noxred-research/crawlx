//! `StateSignature` computation. Pure and wall-clock free.

use crate::minhash::MinHasher;
use crate::roles::{is_text_leaf, is_visible, is_widget};
use crate::simhash::{shingles, simhash};
use crate::text::{mix64, normalize_name_into, Hasher64};
use crate::tree::AxTree;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{FrameInfo, ObservationBundle};
use crawlx_core::state::{MaskSet, StateSignature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// SimHash shingle width over the DFS role/depth stream.
pub const SHINGLE_WIDTH: usize = 3;
/// Depth is clamped to this before it enters a shape token.
pub const MAX_SHAPE_DEPTH: u16 = 15;

const PLACEHOLDER: u64 = 0x6d61_736b_6564_2121; // "masked!!"

const D_ROUTE: &str = "crawlx/state/route/v2";
const D_IDENTITY: &str = "crawlx/state/visible-identity/v1";
const D_FRAMES: &str = "crawlx/state/frame-tree/v1";
const D_NETWORK: &str = "crawlx/state/network-ops/v1";
const D_STORAGE: &str = "crawlx/state/storage-names/v1";

/// Fingerprinting switches.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FingerprintConfig {
    /// Include `browser_storage_digest` (storage/cookie *names*, never values).
    /// Off by default; enabling changes cluster identity.
    pub privacy_gate_storage: bool,
}

/// Signals the bundle does not carry.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ExtraSignals {
    /// Perceptual hash of the page screenshot, when the caller computed one.
    pub visual_phash: Option<u64>,
    /// Storage key names and cookie names. Ignored unless
    /// `FingerprintConfig::privacy_gate_storage` is set.
    pub storage_names: Vec<String>,
}

/// A signature plus the exact affordance sets the cluster compatibility test needs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StateProfile {
    /// The full multi-signal fingerprint the cluster index scores against.
    pub signature: StateSignature,
    /// Sorted unique `role|normalized-name|enabled` token hashes of unmasked widgets.
    pub affordances: Vec<u64>,
    /// Sorted unique `role|normalized-name` token hashes (enabled flag dropped):
    /// the consequence-bearing set that must be identical for a cluster attach.
    pub consequence: Vec<u64>,
}

/// Masked-bundle analysis shared by fingerprinting and diffing.
pub(crate) struct Analysis {
    pub tree: AxTree,
    /// Per node: masked directly or through an ancestor.
    pub masked: Vec<bool>,
}

impl Analysis {
    pub fn new(bundle: &ObservationBundle, masks: &MaskSet) -> Self {
        let tree = AxTree::build(&bundle.ax);
        let masked = if masks.masked_node_keys.is_empty() {
            vec![false; bundle.ax.nodes.len()]
        } else {
            let set: BTreeSet<&Digest> = masks.masked_node_keys.iter().collect();
            let direct: Vec<bool> = tree.keys.iter().map(|k| set.contains(k)).collect();
            tree.inherit(&direct)
        };
        Self { tree, masked }
    }
}

/// Computes `StateSignature`s.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fingerprinter {
    config: FingerprintConfig,
}

impl Fingerprinter {
    /// Fingerprinter with the given switches.
    #[must_use]
    pub const fn new(config: FingerprintConfig) -> Self {
        Self { config }
    }

    /// Signature of `bundle` with `masks` applied.
    #[must_use]
    pub fn fingerprint(&self, bundle: &ObservationBundle, masks: &MaskSet) -> StateSignature {
        self.profile_with(bundle, masks, &ExtraSignals::default())
            .signature
    }

    /// Signature plus affordance sets.
    #[must_use]
    pub fn profile(&self, bundle: &ObservationBundle, masks: &MaskSet) -> StateProfile {
        self.profile_with(bundle, masks, &ExtraSignals::default())
    }

    /// Like [`Self::profile`] with externally supplied pHash and storage names.
    #[must_use]
    pub fn profile_with(
        &self,
        bundle: &ObservationBundle,
        masks: &MaskSet,
        extra: &ExtraSignals,
    ) -> StateProfile {
        let analysis = Analysis::new(bundle, masks);
        let nodes = &bundle.ax.nodes;

        let mut shape: Vec<u64> = Vec::with_capacity(nodes.len());
        let mut affordances: Vec<u64> = Vec::new();
        let mut consequence: Vec<u64> = Vec::new();
        let mut identity: Vec<u64> = Vec::new();
        let mut name = String::new();

        for &i in &analysis.tree.order {
            let node = &nodes[i];
            let depth = analysis.tree.depth[i].min(MAX_SHAPE_DEPTH);
            if analysis.masked[i] {
                // a masked subtree contributes exactly one placeholder token, and a run of
                // adjacent masked sibling subtrees (a feed tail) collapses to one token so
                // the signature does not depend on how long the tail is
                let parent_masked = analysis.tree.parent[i].is_some_and(|p| analysis.masked[p]);
                let prev_masked = analysis.tree.prev_sibling[i].is_some_and(|s| analysis.masked[s]);
                if !parent_masked && !prev_masked {
                    shape.push(mix64(PLACEHOLDER ^ u64::from(depth)));
                }
                continue;
            }
            if node.ignored {
                continue;
            }
            let mut rh = Hasher64::new();
            rh.write_lower(&node.role);
            let role_hash = rh.finish();
            shape.push(mix64(role_hash ^ (u64::from(depth) << 58) ^ u64::from(depth)));

            if !is_visible(node) {
                continue;
            }
            let widget = is_widget(node, &bundle.dom_supplement);
            let is_leaf = is_text_leaf(&node.role);
            if !widget && is_leaf {
                continue;
            }
            normalize_name_into(node.name.as_deref().unwrap_or(""), &mut name);
            if widget {
                let mut h = Hasher64::new();
                h.write_lower(&node.role);
                h.sep();
                h.write(name.as_bytes());
                consequence.push(h.finish());
                h.sep();
                h.write(&[u8::from(!node.disabled)]);
                affordances.push(h.finish());
            }
            if widget || !name.is_empty() {
                let mut h = Hasher64::new();
                h.write_lower(&node.role);
                h.sep();
                h.write(name.as_bytes());
                identity.push(h.finish());
            }
        }

        affordances.sort_unstable();
        affordances.dedup();
        consequence.sort_unstable();
        consequence.dedup();
        identity.sort_unstable();
        identity.dedup();

        let minhash = MinHasher::standard().signature(affordances.iter().copied());
        let signature = StateSignature {
            version: StateSignature::VERSION,
            route_key: route_digest(bundle),
            semantic_affordance_minhash: minhash,
            dom_structure_simhash: simhash(shingles(&shape, SHINGLE_WIDTH)),
            visible_element_identity_digest: u64_set_digest(D_IDENTITY, &identity),
            frame_tree_digest: frame_tree_digest(&bundle.frames),
            network_operation_digest: network_digest(&bundle.network.operations),
            visual_phash: extra.visual_phash,
            browser_storage_digest: self
                .config
                .privacy_gate_storage
                .then(|| storage_digest(&extra.storage_names)),
        };
        StateProfile {
            signature,
            affordances,
            consequence,
        }
    }
}

fn route_digest(bundle: &ObservationBundle) -> Digest {
    use crawlx_core::ParamClass;
    // RouteKey intentionally carries schema only. Tabs, steps and filter buckets can
    // change behavior without changing a single affordance, so preserve those values
    // in the state's hard partition. Resource values remain the ledger's dimension.
    let view_param = |param: &&crawlx_core::url::ClassifiedParam| {
        matches!(
            param.class,
            ParamClass::Navigation | ParamClass::Filter | ParamClass::ActionBearing
        )
    };
    let schema = bundle.route.digest();
    let size = bundle
        .url
        .params
        .iter()
        .filter(view_param)
        .fold(schema.0.len(), |size, param| {
            size.saturating_add(24)
                .saturating_add(param.name.len())
                .saturating_add(param.class.as_str().len())
                .saturating_add(param.value.as_deref().map_or(0, str::len))
        });
    if size == schema.0.len() {
        return Digest::of(D_ROUTE, &schema.0);
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&schema.0);
    for param in bundle.url.params.iter().filter(view_param) {
        for field in [
            param.name.as_str(),
            param.class.as_str(),
            param.value.as_deref().unwrap_or(""),
        ] {
            bytes.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
    }
    Digest::of(D_ROUTE, &bytes)
}

fn u64_set_digest(domain: &str, sorted: &[u64]) -> Digest {
    let mut bytes = Vec::with_capacity(sorted.len() * 8);
    for v in sorted {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    Digest::of(domain, &bytes)
}

fn strings_digest(domain: &str, mut items: Vec<&str>, dedup: bool) -> Digest {
    items.sort_unstable();
    if dedup {
        items.dedup();
    }
    let mut bytes = Vec::new();
    for s in items {
        // lengths beyond u32::MAX saturate: such a string cannot occur in a real bundle
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(s.as_bytes());
    }
    Digest::of(domain, &bytes)
}

fn network_digest(operations: &[String]) -> Digest {
    strings_digest(D_NETWORK, operations.iter().map(String::as_str).collect(), true)
}

fn storage_digest(names: &[String]) -> Digest {
    strings_digest(D_STORAGE, names.iter().map(String::as_str).collect(), true)
}

fn frame_tree_digest(frames: &[FrameInfo]) -> Digest {
    let keys: Vec<String> = frames.iter().map(|f| frame_key(&f.url)).collect();
    strings_digest(D_FRAMES, keys.iter().map(String::as_str).collect(), false)
}

/// `origin|route-template` of a frame URL without a URL parser: the query and
/// fragment are dropped and id-like path segments become `:id`.
fn frame_key(url: &str) -> String {
    let no_frag = url.split('#').next().unwrap_or(url);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    let (origin, path) = match no_query.find("://") {
        Some(p) => {
            let rest = &no_query[p + 3..];
            match rest.find('/') {
                Some(s) => (&no_query[..p + 3 + s], &rest[s..]),
                None => (no_query, ""),
            }
        }
        None => (no_query, ""),
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(origin);
    out.push('|');
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        if is_id_segment(seg) {
            out.push_str(":id");
        } else {
            out.push_str(seg);
        }
    }
    out
}

fn is_id_segment(seg: &str) -> bool {
    if seg.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    let hexish = seg.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    hexish && seg.len() >= 16
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn frame_key_templates_ids() {
        assert_eq!(frame_key("https://a.test/x/123?q=1#h"), "https://a.test|/x/:id");
        assert_eq!(
            frame_key("https://a.test/u/123e4567-e89b-12d3-a456-426614174000"),
            "https://a.test|/u/:id"
        );
        assert_eq!(frame_key("about:blank"), "about:blank|");
    }
}
