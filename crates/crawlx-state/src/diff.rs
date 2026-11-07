//! Affordance diff between two observations, used by novelty strategies.

use crate::roles::{is_visible, is_widget};
use crate::signature::Analysis;
use crate::text::normalize_name;
use crawlx_core::hash::Digest;
use crawlx_core::observation::ObservationBundle;
use crawlx_core::state::MaskSet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A widget at the same structural position whose accessible name changed.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct NameChange {
    /// Lowercased accessible role shared by both widgets.
    pub role: String,
    /// Trimmed accessible name in the first bundle.
    pub before: String,
    /// Trimmed accessible name in the second bundle.
    pub after: String,
}

/// What changed between two observations.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
#[non_exhaustive]
pub struct StateDiffReport {
    /// `role|normalized-name` affordances only in the second bundle.
    pub added_affordances: Vec<String>,
    /// `role|normalized-name` affordances only in the first bundle.
    pub removed_affordances: Vec<String>,
    /// Same-position widgets renamed (not also reported as added/removed).
    pub changed_names: Vec<NameChange>,
    /// Share of the second bundle's affordances that are new or renamed, in `[0, 1]`.
    pub novelty: f32,
}

/// Namespace for diffing.
pub struct StateDiff;

struct Widget {
    key: Digest,
    role: String,
    name: String,
    norm: String,
}

impl Widget {
    fn token(&self) -> String {
        format!("{}|{}", self.role, self.norm)
    }
}

fn widgets(bundle: &ObservationBundle, masks: &MaskSet) -> Vec<Widget> {
    let analysis = Analysis::new(bundle, masks);
    analysis
        .tree
        .order
        .iter()
        .filter(|&&i| !analysis.masked[i])
        .filter_map(|&i| {
            let node = &bundle.ax.nodes[i];
            if !is_visible(node) || !is_widget(node, &bundle.dom_supplement) {
                return None;
            }
            let name = node.name.as_deref().unwrap_or("");
            Some(Widget {
                key: analysis.tree.keys[i],
                role: node.role.to_ascii_lowercase(),
                norm: normalize_name(name),
                name: name.trim().to_owned(),
            })
        })
        .collect()
}

impl StateDiff {
    /// Diff with no masks applied.
    #[must_use]
    pub fn between(a: &ObservationBundle, b: &ObservationBundle) -> StateDiffReport {
        Self::between_masked(a, &MaskSet::default(), b, &MaskSet::default())
    }

    /// Diff of the unmasked widgets of each side.
    #[must_use]
    pub fn between_masked(
        a: &ObservationBundle,
        mask_a: &MaskSet,
        b: &ObservationBundle,
        mask_b: &MaskSet,
    ) -> StateDiffReport {
        let wa = widgets(a, mask_a);
        let wb = widgets(b, mask_b);
        let set_a: BTreeSet<String> = wa.iter().map(Widget::token).collect();
        let set_b: BTreeSet<String> = wb.iter().map(Widget::token).collect();
        let mut added: BTreeSet<String> = set_b.difference(&set_a).cloned().collect();
        let mut removed: BTreeSet<String> = set_a.difference(&set_b).cloned().collect();

        let by_key: BTreeMap<Digest, &Widget> = wa.iter().map(|w| (w.key, w)).collect();
        let mut changed: BTreeSet<NameChange> = BTreeSet::new();
        for w in &wb {
            let Some(old) = by_key.get(&w.key) else { continue };
            if old.role != w.role || old.norm == w.norm {
                continue;
            }
            let (ta, tb) = (old.token(), w.token());
            if removed.contains(&ta) && added.contains(&tb) {
                changed.insert(NameChange {
                    role: w.role.clone(),
                    before: old.name.clone(),
                    after: w.name.clone(),
                });
            }
        }
        for c in &changed {
            removed.remove(&format!("{}|{}", c.role, normalize_name(&c.before)));
            added.remove(&format!("{}|{}", c.role, normalize_name(&c.after)));
        }

        let novelty = if set_b.is_empty() {
            0.0
        } else {
            ((added.len() + changed.len()) as f32 / set_b.len() as f32).min(1.0)
        };
        StateDiffReport {
            added_affordances: added.into_iter().collect(),
            removed_affordances: removed.into_iter().collect(),
            changed_names: changed.into_iter().collect(),
            novelty,
        }
    }
}
