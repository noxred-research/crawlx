//! Bundle helpers: candidate-node selection and stable per-node keys.
//!
//! `ObservationBundle::empty` lives in `crawlx-core`
//! (`crawlx_core::observation::ObservationBundle::empty`).

use crawlx_core::hash::Digest;
use crawlx_core::ids::AxNodeId;
use crawlx_core::observation::{AxNode, AxSnapshot, ObservationBundle};
use std::collections::HashMap;

/// Domain tag of [`node_key`].
pub const NODE_KEY_DOMAIN: &str = "crawlx/node-key/v1";
/// Domain tag of the normalized-name digest inside [`node_key`].
pub const NODE_NAME_DOMAIN: &str = "crawlx/node-name/v1";

const MAX_ANCESTOR_DEPTH: usize = 64;

/// Roles that are interactive widgets (lower-case, as reported by Chromium's AX tree).
const WIDGET_ROLES: &[&str] = &[
    "button",
    "link",
    "textbox",
    "searchbox",
    "combobox",
    "checkbox",
    "radio",
    "switch",
    "slider",
    "spinbutton",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "tab",
    "option",
    "treeitem",
    "listbox",
    "scrollbar",
    "popupbutton",
    "disclosuretriangle",
    "colorwell",
    "datetime",
    "date",
    "textfield",
    "textfieldwithcombobox",
    "comboboxselect",
    "comboboxmenubutton",
    "togglebutton",
    "inputtime",
    "datetimechooser",
];

/// Roles that wrap the whole document and are never candidates themselves.
const DOCUMENT_ROLES: &[&str] = &["rootwebarea", "webarea", "document"];

/// Ancestor roles that carry no structural meaning and are dropped from key paths.
const TRANSPARENT_ROLES: &[&str] = &[
    "generic",
    "none",
    "presentation",
    "group",
    "genericcontainer",
    "div",
];

/// Is `role` an interactive widget role?
#[must_use]
pub fn is_widget_role(role: &str) -> bool {
    let lower = role.to_ascii_lowercase();
    WIDGET_ROLES.contains(&lower.as_str())
}

/// Candidate interactable nodes: not ignored, and either a widget role or focusable.
pub fn candidate_nodes(bundle: &ObservationBundle) -> impl Iterator<Item = &AxNode> {
    bundle.ax.nodes.iter().filter(|n| is_candidate(n))
}

/// The candidate rule behind [`candidate_nodes`].
#[must_use]
pub fn is_candidate(node: &AxNode) -> bool {
    if node.ignored {
        return false;
    }
    let lower = node.role.to_ascii_lowercase();
    if DOCUMENT_ROLES.contains(&lower.as_str()) {
        return false;
    }
    node.focusable || WIDGET_ROLES.contains(&lower.as_str())
}

/// Strip what varies without meaning from an accessible name: digits and
/// whitespace runs (`"12:03 PM"` → `": PM"`, `"Cart (3)"` → `"Cart ()"`).
#[must_use]
pub fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending_space = false;
    for c in name.chars() {
        if c.is_ascii_digit() {
            continue;
        }
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    out
}

/// Parent-link index over one snapshot; amortizes ancestor walks when keys are
/// needed for many nodes.
pub struct AxIndex<'a> {
    snapshot: &'a AxSnapshot,
    by_id: HashMap<&'a AxNodeId, usize>,
}

impl<'a> AxIndex<'a> {
    /// Index `snapshot` by AX node id. Nodes without an id cannot be found as parents.
    #[must_use]
    pub fn new(snapshot: &'a AxSnapshot) -> Self {
        let mut by_id = HashMap::with_capacity(snapshot.nodes.len());
        for (i, n) in snapshot.nodes.iter().enumerate() {
            if let Some(id) = &n.locator.ax_node_id {
                by_id.insert(id, i);
            }
        }
        Self { snapshot, by_id }
    }

    /// The snapshot this index was built over.
    #[must_use]
    pub fn snapshot(&self) -> &'a AxSnapshot {
        self.snapshot
    }

    fn parent_of(&self, node: &AxNode) -> Option<&'a AxNode> {
        let pid = node.parent.as_ref()?;
        let idx = *self.by_id.get(pid)?;
        self.snapshot.nodes.get(idx)
    }

    /// Ancestors, nearest first, bounded; a malformed cyclic tree terminates.
    pub fn ancestors<'s>(&'s self, node: &'s AxNode) -> impl Iterator<Item = &'a AxNode> + 's {
        let mut cur = self.parent_of(node);
        let mut depth = 0usize;
        std::iter::from_fn(move || {
            let n = cur?;
            depth += 1;
            if depth > MAX_ANCESTOR_DEPTH {
                cur = None;
                return None;
            }
            cur = self.parent_of(n);
            Some(n)
        })
    }

    /// Ancestor role path, outermost first, without structure-free roles.
    #[must_use]
    pub fn ancestor_roles(&self, node: &AxNode) -> Vec<String> {
        let mut path: Vec<String> = self
            .ancestors(node)
            .filter(|a| !a.ignored)
            .map(|a| a.role.to_ascii_lowercase())
            .filter(|r| !TRANSPARENT_ROLES.contains(&r.as_str()))
            .collect();
        path.reverse();
        path
    }

    /// `node_key` with the ancestor walk served by this index.
    #[must_use]
    pub fn node_key(&self, node: &AxNode) -> Digest {
        key_from_parts(
            &node.role,
            &self.ancestor_roles(node),
            node.name.as_deref().unwrap_or(""),
        )
    }
}

pub(crate) fn key_from_parts(role: &str, ancestor_path: &[String], name: &str) -> Digest {
    let name_digest = Digest::of(NODE_NAME_DOMAIN, normalize_name(name).as_bytes());
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(role.to_ascii_lowercase().as_bytes());
    buf.push(0);
    for (i, r) in ancestor_path.iter().enumerate() {
        if i > 0 {
            buf.push(b'/');
        }
        buf.extend_from_slice(r.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&name_digest.0);
    Digest::of(NODE_KEY_DOMAIN, &buf)
}

/// Stable key of `node` within `snapshot`:
/// `Digest::of("crawlx/node-key/v1", role ‖ ancestor-path ‖ name-digest)`.
/// The name digest is taken over the normalized name (digits and whitespace
/// runs stripped), so a clock or counter keeps its key while it ticks.
/// Builds an index per call; use [`AxIndex::node_key`] for many nodes.
#[must_use]
pub fn node_key(node: &AxNode, snapshot: &AxSnapshot) -> Digest {
    AxIndex::new(snapshot).node_key(node)
}

#[cfg(test)]
pub(crate) mod testutil {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::ids::{BackendNodeId, FrameId, SessionId, TabId};
    use crawlx_core::observation::RuntimeLocator;
    use crawlx_core::ObservationEpoch;
    use crawlx_url::{CanonicalizeOptions, Canonicalizer};
    use std::collections::BTreeMap;

    pub fn locator(id: &str, n: i64) -> RuntimeLocator {
        RuntimeLocator {
            tab: TabId("tab".to_owned()),
            frame: FrameId("main".to_owned()),
            backend_node_id: BackendNodeId(n),
            object_id: None,
            ax_node_id: Some(AxNodeId(id.to_owned())),
            epoch: ObservationEpoch::default(),
        }
    }

    pub fn node(id: &str, parent: Option<&str>, role: &str, name: &str) -> AxNode {
        AxNode {
            locator: locator(id, id.bytes().map(i64::from).sum()),
            role: role.to_owned(),
            name: Some(name.to_owned()),
            description: None,
            value: None,
            ignored: false,
            focusable: false,
            disabled: false,
            expanded: None,
            checked: None,
            properties: BTreeMap::new(),
            parent: parent.map(|p| AxNodeId(p.to_owned())),
            children: Vec::new(),
            bbox: None,
        }
    }

    pub fn snapshot(nodes: Vec<AxNode>) -> AxSnapshot {
        AxSnapshot { nodes }
    }

    pub fn canonical(url: &str) -> crawlx_core::CanonicalUrl {
        let u = url::Url::parse(url).unwrap();
        Canonicalizer::canonicalize_url(&u, &CanonicalizeOptions::default()).unwrap()
    }

    pub fn bundle(url: &str) -> ObservationBundle {
        ObservationBundle::empty(SessionId::new(), TabId("tab".to_owned()), canonical(url))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::testutil::*;
    use super::*;

    #[test]
    fn candidates_are_widgets_or_focusable_and_not_ignored() {
        let mut b = bundle("https://example.com/");
        let mut focusable_div = node("3", Some("1"), "generic", "tabbable");
        focusable_div.focusable = true;
        let mut ignored_button = node("4", Some("1"), "button", "hidden");
        ignored_button.ignored = true;
        let mut root = node("1", None, "RootWebArea", "page");
        root.focusable = true;
        b.ax = snapshot(vec![
            root,
            node("2", Some("1"), "button", "Save"),
            focusable_div,
            ignored_button,
            node("5", Some("1"), "paragraph", "text"),
            node("6", Some("1"), "Link", "Home"),
        ]);
        let names: Vec<_> = candidate_nodes(&b).map(|n| n.name.clone().unwrap()).collect();
        assert_eq!(names, vec!["Save", "tabbable", "Home"]);
    }

    #[test]
    fn node_key_is_stable_across_digit_changes_and_sensitive_to_role_and_path() {
        let s1 = snapshot(vec![
            node("1", None, "RootWebArea", ""),
            node("2", Some("1"), "banner", ""),
            node("3", Some("2"), "generic", ""),
            node("4", Some("3"), "StaticText", "12:03 PM"),
        ]);
        let s2 = snapshot(vec![
            node("1", None, "RootWebArea", ""),
            node("2", Some("1"), "banner", ""),
            node("4", Some("2"), "StaticText", "12:04  PM"),
        ]);
        let k1 = node_key(&s1.nodes[3], &s1);
        let k2 = node_key(&s2.nodes[2], &s2);
        assert_eq!(k1, k2, "generic wrappers and digits do not change the key");

        let s3 = snapshot(vec![
            node("1", None, "RootWebArea", ""),
            node("2", Some("1"), "main", ""),
            node("4", Some("2"), "StaticText", "12:04 PM"),
        ]);
        assert_ne!(k1, node_key(&s3.nodes[2], &s3), "different ancestor path");
        let s4 = snapshot(vec![
            node("1", None, "RootWebArea", ""),
            node("2", Some("1"), "banner", ""),
            node("4", Some("2"), "button", "12:04 PM"),
        ]);
        assert_ne!(k1, node_key(&s4.nodes[2], &s4), "different role");
    }

    #[test]
    fn cyclic_parent_links_terminate() {
        let s = snapshot(vec![
            node("1", Some("2"), "group", "a"),
            node("2", Some("1"), "group", "b"),
        ]);
        let idx = AxIndex::new(&s);
        assert!(idx.ancestors(&s.nodes[0]).count() <= MAX_ANCESTOR_DEPTH);
        let _ = idx.node_key(&s.nodes[0]);
    }

    #[test]
    fn normalize_strips_digits_and_collapses_whitespace() {
        assert_eq!(normalize_name("  Cart   (3)  items "), "Cart () items");
        assert_eq!(normalize_name("12:03 PM"), ": PM");
    }
}
