//! Role classification used by masking, fingerprinting and diffing.

use crate::tree::has_listeners;
use crawlx_core::observation::{AxNode, DomSupplement};

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
    "tab",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "option",
    "treeitem",
    "togglebutton",
    "popupbutton",
    "disclosuretriangle",
    "comboboxselect",
    "comboboxmenubutton",
    "menulistoption",
    "listboxoption",
    "textfield",
    "textfieldwithcombobox",
    "colorwell",
    "datetime",
    "date",
    "inputtime",
];

const TEXT_LEAF_ROLES: &[&str] = &["statictext", "text", "inlinetextbox", "linebreak", "paragraph"];

/// Generic containers that count as widgets when focusable or listening.
const CUSTOM_CONTROL_ROLES: &[&str] = &["generic", "group", "none", "presentation", "div", "span"];

const LIVE_ROLES: &[&str] = &["log", "status", "marquee"];
const CLOCK_ROLES: &[&str] = &["timer", "time"];
const FEED_ROLES: &[&str] = &["feed", "list"];

fn any_eq(set: &[&str], role: &str) -> bool {
    set.iter().any(|r| r.eq_ignore_ascii_case(role))
}

#[must_use]
pub fn is_text_leaf(role: &str) -> bool {
    any_eq(TEXT_LEAF_ROLES, role)
}

#[must_use]
pub fn is_live_role(role: &str) -> bool {
    any_eq(LIVE_ROLES, role)
}

#[must_use]
pub fn is_clock_role(role: &str) -> bool {
    any_eq(CLOCK_ROLES, role)
}

#[must_use]
pub fn is_feed_role(role: &str) -> bool {
    any_eq(FEED_ROLES, role)
}

/// Is the node an interactable control (a consequence-bearing affordance)?
/// Role-based, plus generic containers that are focusable or carry listeners.
#[must_use]
pub fn is_widget(node: &AxNode, supplement: &DomSupplement) -> bool {
    if node.ignored {
        return false;
    }
    if any_eq(WIDGET_ROLES, &node.role) {
        return true;
    }
    any_eq(CUSTOM_CONTROL_ROLES, &node.role) && (node.focusable || has_listeners(node, supplement))
}

/// Visible: not ignored and, when a box is known, non-empty.
#[must_use]
pub fn is_visible(node: &AxNode) -> bool {
    !node.ignored && node.bbox.is_none_or(|b| b.area() > 0.0)
}

/// `aria-live` other than `off`, from either AX property spelling.
#[must_use]
pub fn is_live_region(node: &AxNode) -> bool {
    ["live", "aria-live"].iter().any(|k| {
        node.properties
            .get(*k)
            .is_some_and(|v| !v.is_empty() && !v.eq_ignore_ascii_case("off"))
    })
}
