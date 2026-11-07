//! `ObservedDescriptor` assembly: all evidence for one candidate in one
//! observation. Descriptors are never identities.

use std::collections::BTreeMap;

use crawlx_core::observation::{AxNode, BoundingBox, DomNodeSupplement, ObservedDescriptor};

use crate::index::BundleIndex;
use crate::normalize::{
    collapse_ws, container_signature, control_type, encode_container, is_landmark_role, is_wrapper_role,
    label_signature, normalize_accessible_name, stable_ancestor_role_path, truncate_chars,
    MAX_CONTAINER_DEPTH,
};

/// AX properties mirrored into descriptor attributes as `aria-{name}` when the
/// DOM does not already carry the attribute.
const MIRRORED_AX_PROPERTIES: [&str; 10] = [
    "haspopup",
    "pressed",
    "selected",
    "orientation",
    "multiselectable",
    "required",
    "readonly",
    "modal",
    "autocomplete",
    "controls",
];

/// Names longer than this are cut when synthesised from DOM text.
const MAX_FALLBACK_NAME_CHARS: usize = 200;

/// Role implied by native HTML semantics, as Chromium maps it to AX.
#[must_use]
pub fn native_role(tag: &str, attrs: &BTreeMap<String, String>) -> Option<&'static str> {
    let attr = |k: &str| attrs.get(k).map(|v| v.trim().to_ascii_lowercase());
    match tag.to_ascii_lowercase().as_str() {
        "a" | "area" => attrs.contains_key("href").then_some("link"),
        "button" | "summary" => Some("button"),
        "select" => Some(
            if attrs.contains_key("multiple") || attr("size").is_some_and(|s| s != "1" && s != "0") {
                "listbox"
            } else {
                "combobox"
            },
        ),
        "textarea" => Some("textbox"),
        "option" => Some("option"),
        "input" => match attr("type").as_deref().unwrap_or("text") {
            "hidden" => None,
            "button" | "submit" | "reset" | "image" | "file" | "color" => Some("button"),
            "checkbox" => Some("checkbox"),
            "radio" => Some("radio"),
            "range" => Some("slider"),
            "number" => Some("spinbutton"),
            "search" => Some("searchbox"),
            _ => Some("textbox"),
        },
        _ => attr("contenteditable")
            .is_some_and(|v| v != "false")
            .then_some("textbox"),
    }
}

/// Builds descriptors against one bundle index.
pub struct DescriptorBuilder<'a> {
    index: &'a BundleIndex<'a>,
}

impl<'a> DescriptorBuilder<'a> {
    /// Builder over `index`; descriptors are assembled from the bundle it indexes.
    #[must_use]
    pub fn new(index: &'a BundleIndex<'a>) -> Self {
        Self { index }
    }

    /// Assemble the descriptor for the node `backend`. `ax` is its AX node and
    /// `dom` its supplement when the observation captured them.
    #[must_use]
    pub fn build(
        &self,
        ax: Option<&AxNode>,
        dom: Option<&DomNodeSupplement>,
        backend: i64,
    ) -> ObservedDescriptor {
        let tag = dom
            .map(|d| d.tag.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty());
        let mut attributes = dom.map(|d| d.attributes.clone()).unwrap_or_default();
        if let Some(ax) = ax {
            mirror_ax_state(ax, &mut attributes);
        }
        let role = resolve_role(ax, tag.as_deref(), &attributes);
        let locator = ax
            .map(|n| n.locator.clone())
            .unwrap_or_else(|| self.index.dom_locator(backend));

        let accessible_name = ax
            .and_then(|n| n.name.as_deref())
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_owned)
            .or_else(|| fallback_name(dom, &attributes));
        let description = ax
            .and_then(|n| n.description.as_deref())
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_owned);
        let href = match tag.as_deref() {
            Some("a" | "area") => attributes
                .get("href")
                .map(|h| h.trim().to_owned())
                .filter(|h| !h.is_empty()),
            _ => None,
        };
        let bbox = dom.and_then(|d| d.bbox).or_else(|| ax.and_then(|n| n.bbox));
        let ancestors = ax.map(|n| self.index.ancestors(n)).unwrap_or_default();
        let mut ancestor_roles: Vec<String> = ancestors.iter().map(|a| a.role.clone()).collect();
        ancestor_roles.reverse();
        let focusable = ax.is_some_and(|n| n.focusable) || tabindex_focusable(&attributes);
        let disabled = ax.is_some_and(|n| n.disabled)
            || attributes.contains_key("disabled")
            || attributes
                .get("aria-disabled")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));

        ObservedDescriptor {
            frame_lineage: self.index.lineage(&locator.frame),
            locator,
            role,
            accessible_name,
            description,
            tag,
            visible: is_visible(bbox.as_ref(), &attributes),
            href,
            bbox,
            ancestor_roles,
            container_text: self.container_hint(&ancestors),
            focusable,
            disabled,
            listeners: dom.map(|d| d.listeners.clone()).unwrap_or_default(),
            cursor: dom.and_then(|d| d.cursor.clone()),
            in_closed_shadow_root: dom.is_some_and(|d| d.in_shadow_root && d.shadow_root_closed),
            text: dom.and_then(|d| d.text.clone()),
            attributes,
            instance_ordinal: 0,
        }
    }

    /// Nearest named container, searched through at most
    /// [`MAX_CONTAINER_DEPTH`] stable (non-wrapper) ancestors: a named
    /// landmark, a heading/link ancestor, or the first named heading among an
    /// ancestor's children (looking through wrappers). Encoded as
    /// `"{role}|{text}"`, text truncated to 50 characters.
    fn container_hint(&self, ancestors: &[&AxNode]) -> Option<String> {
        let mut depth = 0;
        for &anc in ancestors {
            if is_wrapper_role(&anc.role) {
                continue;
            }
            depth += 1;
            if depth > MAX_CONTAINER_DEPTH {
                break;
            }
            let role = anc.role.to_ascii_lowercase();
            let name = anc.name.as_deref().map(collapse_ws).filter(|n| !n.is_empty());
            if let Some(name) = &name {
                if is_landmark_role(&role) || role == "heading" || role == "link" {
                    return Some(encode_container(&role, name));
                }
            }
            if let Some(h) = self.heading_child(anc, 0) {
                return Some(encode_container("heading", &h));
            }
        }
        None
    }

    fn heading_child(&self, anc: &AxNode, depth: usize) -> Option<String> {
        for child in self.index.children(anc) {
            let role = child.role.to_ascii_lowercase();
            if role == "heading" {
                if let Some(n) = child.name.as_deref().map(collapse_ws).filter(|n| !n.is_empty()) {
                    return Some(n);
                }
            } else if is_wrapper_role(&role) && depth < MAX_CONTAINER_DEPTH {
                if let Some(n) = self.heading_child(child, depth + 1) {
                    return Some(n);
                }
            }
        }
        None
    }
}

fn resolve_role(ax: Option<&AxNode>, tag: Option<&str>, attrs: &BTreeMap<String, String>) -> String {
    if let Some(n) = ax {
        if !is_wrapper_role(&n.role) {
            return n.role.trim().to_ascii_lowercase();
        }
    }
    if let Some(r) = attrs
        .get("role")
        .and_then(|r| r.split_whitespace().next())
        .map(str::to_ascii_lowercase)
        .filter(|r| !is_wrapper_role(r))
    {
        return r;
    }
    if let Some(r) = tag.and_then(|t| native_role(t, attrs)) {
        return r.to_owned();
    }
    ax.map(|n| n.role.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "generic".to_owned())
}

fn mirror_ax_state(ax: &AxNode, attrs: &mut BTreeMap<String, String>) {
    if let Some(e) = ax.expanded {
        attrs
            .entry("aria-expanded".to_owned())
            .or_insert_with(|| e.to_string());
    }
    if let Some(c) = &ax.checked {
        attrs
            .entry("aria-checked".to_owned())
            .or_insert_with(|| c.clone());
    }
    for name in MIRRORED_AX_PROPERTIES {
        if let Some(v) = ax.properties.get(name) {
            attrs.entry(format!("aria-{name}")).or_insert_with(|| v.clone());
        }
    }
}

fn fallback_name(dom: Option<&DomNodeSupplement>, attrs: &BTreeMap<String, String>) -> Option<String> {
    let from_attr = ["aria-label", "alt", "title", "placeholder", "value"]
        .iter()
        .filter_map(|k| attrs.get(*k))
        .map(|v| collapse_ws(v))
        .find(|v| !v.is_empty());
    from_attr
        .or_else(|| {
            dom.and_then(|d| d.text.as_deref())
                .map(collapse_ws)
                .filter(|t| !t.is_empty())
        })
        .map(|n| truncate_chars(&n, MAX_FALLBACK_NAME_CHARS))
}

fn tabindex_focusable(attrs: &BTreeMap<String, String>) -> bool {
    attrs
        .get("tabindex")
        .and_then(|t| t.trim().parse::<i32>().ok())
        .is_some_and(|t| t >= 0)
}

fn is_visible(bbox: Option<&BoundingBox>, attrs: &BTreeMap<String, String>) -> bool {
    if attrs.contains_key("hidden") {
        return false;
    }
    if attrs
        .get("aria-hidden")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
    {
        return false;
    }
    // Unknown geometry is not contradicted evidence: keep the node.
    bbox.is_none_or(|b| b.area() > 0.0)
}

/// Fill `instance_ordinal`: the rank of each descriptor, in the given
/// (document) order, among descriptors sharing its normalized template
/// (frame lineage, role, name, stable ancestor path, container, control type,
/// label). Repeated cards therefore get 0, 1, 2, … while sharing one identity.
///
/// Accepts any iterator of mutable descriptors so callers that embed them in
/// larger records need not clone them out.
pub fn assign_instance_ordinals<'a>(descriptors: impl IntoIterator<Item = &'a mut ObservedDescriptor>) {
    type Key = (
        Vec<String>,
        String,
        String,
        Vec<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut counters: BTreeMap<Key, u32> = BTreeMap::new();
    for d in descriptors {
        let name = d
            .accessible_name
            .as_deref()
            .or(d.text.as_deref())
            .map(normalize_accessible_name)
            .unwrap_or_default();
        let key: Key = (
            d.frame_lineage.clone(),
            d.role.to_ascii_lowercase(),
            name,
            stable_ancestor_role_path(&d.ancestor_roles),
            container_signature(d.container_text.as_deref()),
            control_type(d.tag.as_deref(), &d.attributes),
            label_signature(&d.role, d.tag.as_deref(), &d.attributes),
        );
        let slot = counters.entry(key).or_insert(0);
        d.instance_ordinal = *slot;
        *slot += 1;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn attrs(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn native_roles() {
        assert_eq!(native_role("a", &attrs(&[("href", "/x")])), Some("link"));
        assert_eq!(native_role("a", &attrs(&[])), None);
        assert_eq!(native_role("button", &attrs(&[])), Some("button"));
        assert_eq!(native_role("summary", &attrs(&[])), Some("button"));
        assert_eq!(
            native_role("input", &attrs(&[("type", "checkbox")])),
            Some("checkbox")
        );
        assert_eq!(native_role("input", &attrs(&[("type", "range")])), Some("slider"));
        assert_eq!(
            native_role("input", &attrs(&[("type", "number")])),
            Some("spinbutton")
        );
        assert_eq!(native_role("input", &attrs(&[("type", "hidden")])), None);
        assert_eq!(native_role("input", &attrs(&[])), Some("textbox"));
        assert_eq!(native_role("select", &attrs(&[])), Some("combobox"));
        assert_eq!(
            native_role("select", &attrs(&[("multiple", "")])),
            Some("listbox")
        );
        assert_eq!(
            native_role("div", &attrs(&[("contenteditable", "true")])),
            Some("textbox")
        );
        assert_eq!(native_role("div", &attrs(&[])), None);
    }

    #[test]
    fn visibility_rules() {
        let b = BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 10.0,
            height: 10.0,
        };
        assert!(is_visible(Some(&b), &attrs(&[])));
        assert!(is_visible(None, &attrs(&[])));
        assert!(!is_visible(Some(&BoundingBox::default()), &attrs(&[])));
        assert!(!is_visible(Some(&b), &attrs(&[("hidden", "")])));
        assert!(!is_visible(Some(&b), &attrs(&[("aria-hidden", "true")])));
    }

    #[test]
    fn tabindex() {
        assert!(tabindex_focusable(&attrs(&[("tabindex", "0")])));
        assert!(!tabindex_focusable(&attrs(&[("tabindex", "-1")])));
        assert!(!tabindex_focusable(&attrs(&[])));
    }
}

#[cfg(test)]
mod page_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use crate::ladder::{CandidateDiscovery, DiscoveryConfig};
    use crate::testutil::card_page;

    #[test]
    fn card_descriptors_carry_container_ancestors_and_ordinals() {
        let page = card_page(&["Blue Widget", "Red Widget", "Green Widget"], 2, 3);
        let cands = CandidateDiscovery::discover(&page.bundle, &DiscoveryConfig::default());
        assert_eq!(cands.len(), 3);
        for (i, c) in cands.iter().enumerate() {
            let d = &c.descriptor;
            assert_eq!(d.role, "button");
            assert_eq!(d.instance_ordinal, u32::try_from(i).unwrap());
            assert_eq!(
                d.ancestor_roles,
                ["rootwebarea", "main", "list", "listitem", "generic", "generic"]
                    .iter()
                    .map(|r| if *r == "rootwebarea" {
                        "RootWebArea".to_owned()
                    } else {
                        (*r).to_owned()
                    })
                    .collect::<Vec<_>>()
            );
            assert_eq!(d.tag.as_deref(), Some("button"));
            assert!(d.focusable && d.visible && !d.disabled);
        }
        assert_eq!(
            cands[0].descriptor.container_text.as_deref(),
            Some("heading|Blue Widget")
        );
        assert_eq!(
            cands[2].descriptor.container_text.as_deref(),
            Some("heading|Green Widget")
        );
    }

    #[test]
    fn container_search_depth_ignores_wrappers() {
        // 6 wrappers between listitem and button must not push the heading out of reach.
        let page = card_page(&["Blue Widget"], 6, 0);
        let cands = CandidateDiscovery::discover(&page.bundle, &DiscoveryConfig::default());
        assert_eq!(
            cands[0].descriptor.container_text.as_deref(),
            Some("heading|Blue Widget")
        );
    }

    #[test]
    fn long_container_text_is_truncated_to_50() {
        let long = "x".repeat(120);
        let page = card_page(&[long.as_str()], 0, 0);
        let cands = CandidateDiscovery::discover(&page.bundle, &DiscoveryConfig::default());
        let text = cands[0].descriptor.container_text.clone().unwrap();
        assert_eq!(text.chars().count(), "heading|".len() + 50);
    }
}
