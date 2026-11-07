//! Volatile-region masks. Masks keep a signature stable
//! without hiding functionality; they are stored with the state so a
//! fingerprint is reproducible from its artifact.

use crate::roles::{is_clock_role, is_feed_role, is_live_region, is_live_role};
use crate::tree::AxTree;
use crawlx_core::hash::Digest;
use crawlx_core::observation::ObservationBundle;
use crawlx_core::state::{MaskReason, MaskSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current `MaskSet.version`.
pub const MASK_VERSION: u16 = 1;

/// A node another component (no-action probe, repeated-diff tracker) found volatile.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct VolatileHint {
    /// Stable node key (see [`MaskBuilder::node_keys`]) of the volatile node.
    pub node_key: Digest,
    /// Why the node is considered volatile.
    pub reason: MaskReason,
}

/// Configured mask: role equality and/or accessible-name substring (case-insensitive).
/// A selector with neither field never matches.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub struct MaskSelector {
    /// Accessible role to match, case-insensitively; `None` matches any role.
    pub role: Option<String>,
    /// Substring of the accessible name to match, case-insensitively; `None` matches any name.
    pub name_contains: Option<String>,
}

/// Mask derivation switches.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct MaskConfig {
    /// Mask `aria-live` regions and `timer`/`log`/`status`/`marquee` roles.
    pub live_regions: bool,
    /// `feed`/`list` containers with more than this many children keep the first
    /// `feed_keep` and mask the rest (planning default 20).
    pub feed_keep: usize,
    /// Selectors masking any node they match, regardless of structure.
    pub configured: Vec<MaskSelector>,
}

impl Default for MaskConfig {
    fn default() -> Self {
        Self {
            live_regions: true,
            feed_keep: 20,
            configured: Vec::new(),
        }
    }
}

/// Builds `MaskSet`s.
pub struct MaskBuilder;

impl MaskBuilder {
    /// Derive the masks of `bundle` from structure, `hints` and `config`.
    /// Output keys are sorted and `reasons[i]` explains `masked_node_keys[i]`.
    #[must_use]
    pub fn build(bundle: &ObservationBundle, hints: &[VolatileHint], config: &MaskConfig) -> MaskSet {
        let tree = AxTree::build(&bundle.ax);
        let nodes = &bundle.ax.nodes;
        let mut masked: BTreeMap<Digest, MaskReason> = BTreeMap::new();

        for (i, node) in nodes.iter().enumerate() {
            if config.live_regions {
                if is_clock_role(&node.role) {
                    masked.entry(tree.keys[i]).or_insert(MaskReason::ClockOrCounter);
                } else if is_live_role(&node.role) || is_live_region(node) {
                    masked.entry(tree.keys[i]).or_insert(MaskReason::LiveRegion);
                }
            }
            if config
                .configured
                .iter()
                .any(|s| selector_matches(s, &node.role, node.name.as_deref()))
            {
                masked.entry(tree.keys[i]).or_insert(MaskReason::Configured);
            }
            if is_feed_role(&node.role) && tree.children[i].len() > config.feed_keep {
                for &c in &tree.children[i][config.feed_keep..] {
                    masked
                        .entry(tree.keys[c])
                        .or_insert(MaskReason::FeedBeyondFirstPage);
                }
            }
        }
        for h in hints {
            masked.entry(h.node_key).or_insert_with(|| h.reason.clone());
        }

        let mut set = MaskSet {
            version: MASK_VERSION,
            masked_node_keys: Vec::with_capacity(masked.len()),
            reasons: Vec::with_capacity(masked.len()),
        };
        for (k, r) in masked {
            set.masked_node_keys.push(k);
            set.reasons.push(r);
        }
        set
    }

    /// Stable node keys of `bundle`, parallel to `bundle.ax.nodes`. Components
    /// that detect volatility themselves use these to form [`VolatileHint`]s.
    #[must_use]
    pub fn node_keys(bundle: &ObservationBundle) -> Vec<Digest> {
        AxTree::build(&bundle.ax).keys
    }

    /// No-action probe (mask source 2): nodes whose name, value or
    /// description differ between `first` and `probe`, a re-observation
    /// without acting, become `ChangedWithoutAction` hints.
    #[must_use]
    pub fn probe_hints(first: &ObservationBundle, probe: &ObservationBundle) -> Vec<VolatileHint> {
        let before = node_facts(first);
        let after = node_facts(probe);
        before
            .iter()
            .filter(|(k, f)| after.get(*k).is_some_and(|g| g != *f))
            .map(|(k, _)| VolatileHint {
                node_key: *k,
                reason: MaskReason::ChangedWithoutAction,
            })
            .collect()
    }
}

type Facts<'a> = (Option<&'a str>, Option<&'a str>, Option<&'a str>);

fn node_facts(b: &ObservationBundle) -> BTreeMap<Digest, Facts<'_>> {
    let keys = AxTree::build(&b.ax).keys;
    b.ax.nodes
        .iter()
        .zip(keys)
        .map(|(n, k)| {
            (
                k,
                (n.name.as_deref(), n.value.as_deref(), n.description.as_deref()),
            )
        })
        .collect()
}

fn selector_matches(sel: &MaskSelector, role: &str, name: Option<&str>) -> bool {
    if sel.role.is_none() && sel.name_contains.is_none() {
        return false;
    }
    if let Some(r) = &sel.role {
        if !r.eq_ignore_ascii_case(role) {
            return false;
        }
    }
    if let Some(needle) = &sel.name_contains {
        let hay = name.unwrap_or("").to_lowercase();
        if !hay.contains(&needle.to_lowercase()) {
            return false;
        }
    }
    true
}
