//! Role-driven action vocabulary.
//!
//! | role | kinds |
//! |---|---|
//! | `button`, `link`, `summary` | Click, KeyboardActivate |
//! | `textbox`, `searchbox` | Type |
//! | `checkbox`, `switch` | SetChecked |
//! | `radio` | Click |
//! | `combobox`, `listbox` | Select (+ Type for an editable, non-`select` combobox) |
//! | `slider`, `spinbutton` | SetRange |
//! | `tab`, `treeitem`, `menuitem*` | Click, Keys |
//! | `option` | Click, KeyboardActivate |
//! | expandable (`aria-expanded`, `disclosure`) | + Click |
//! | `input[type=file]` | Upload (only) |
//! | `aria-haspopup`, `menu`, `menubar`, hover-class listener | + Hover |
//! | `draggable="true"` | + Drag |
//! | scroll container (`feed`, `log`, `scrollbar`, or `overflow(-x/-y)` `auto|scroll`) | + Scroll |

use crawlx_core::identity::ActionKind;

use crate::ladder::Candidate;

/// Action vocabulary of controls.
pub struct ActionVocabulary;

impl ActionVocabulary {
    /// Kinds a bare `role` supports, sorted and unique.
    #[must_use]
    pub fn for_role(role: &str) -> Vec<ActionKind> {
        let role = role.trim().to_ascii_lowercase();
        let mut kinds: Vec<ActionKind> = match role.as_str() {
            "button" | "link" | "option" => vec![ActionKind::Click, ActionKind::KeyboardActivate],
            "textbox" | "searchbox" => vec![ActionKind::Type],
            "checkbox" | "switch" => vec![ActionKind::SetChecked],
            "radio" => vec![ActionKind::Click],
            "combobox" | "listbox" => vec![ActionKind::Select],
            "slider" | "spinbutton" => vec![ActionKind::SetRange],
            "tab" | "treeitem" => vec![ActionKind::Click, ActionKind::Keys],
            r if r.starts_with("menuitem") => vec![ActionKind::Click, ActionKind::Keys],
            "disclosure" | "disclosuretriangle" => vec![ActionKind::Click],
            "popupbutton" | "comboboxselect" | "comboboxmenubutton" => vec![ActionKind::Select],
            "menu" | "menubar" => vec![ActionKind::Hover],
            "feed" | "log" | "scrollbar" => vec![ActionKind::Scroll],
            _ => Vec::new(),
        };
        normalize(&mut kinds);
        kinds
    }

    /// Kinds a candidate supports: the role's, refined by tag, `type` and
    /// ARIA/DOM attributes.
    #[must_use]
    pub fn for_candidate(c: &Candidate) -> Vec<ActionKind> {
        let d = &c.descriptor;
        let attr = |k: &str| d.attributes.get(k).map(|v| v.trim().to_ascii_lowercase());
        let tag = d.tag.as_deref().map(str::to_ascii_lowercase);

        if tag.as_deref() == Some("input") && attr("type").as_deref() == Some("file") {
            return vec![ActionKind::Upload];
        }

        let mut kinds = Self::for_role(&d.role);
        let role = d.role.to_ascii_lowercase();

        // Editable combobox (autocomplete input) also accepts text.
        if role == "combobox" && tag.as_deref() != Some("select") && tag.is_some() {
            kinds.push(ActionKind::Type);
        }
        // Native <summary> and disclosure widgets.
        if tag.as_deref() == Some("summary") {
            kinds.push(ActionKind::Click);
        }
        // Expandable.
        if attr("aria-expanded").is_some() {
            kinds.push(ActionKind::Click);
        }
        // Hover-revealing.
        if attr("aria-haspopup").is_some_and(|v| v != "false") {
            kinds.push(ActionKind::Hover);
        }
        // Draggable: the attribute, a grab cursor or a drag listener (ladder evidence).
        if attr("draggable").as_deref() == Some("true") || c.evidence.draggable {
            kinds.push(ActionKind::Drag);
        }
        // Scroll container.
        let overflow_scrolls = ["overflow", "overflow-x", "overflow-y"]
            .iter()
            .filter_map(|k| attr(k))
            .any(|v| v == "auto" || v == "scroll");
        if overflow_scrolls {
            kinds.push(ActionKind::Scroll);
        }
        // A generic node found only through listeners or cursor can be clicked.
        if kinds.is_empty()
            && (c.evidence.direct_listener || c.evidence.action_cursor || c.evidence.focusable)
        {
            kinds.push(ActionKind::Click);
            if c.evidence.focusable {
                kinds.push(ActionKind::KeyboardActivate);
            }
        }
        // A hover-class listener on the node makes it a hover target (G13 hover menus),
        // on top of whatever else it supports.
        if c.evidence.hover_listener {
            kinds.push(ActionKind::Hover);
        }
        normalize(&mut kinds);
        kinds
    }
}

fn normalize(kinds: &mut Vec<ActionKind>) {
    kinds.sort();
    kinds.dedup();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::ladder::{CandidateEvidence, Rung};
    use crate::testutil::{attrs, descriptor};

    fn cand(role: &str, tag: Option<&str>, kv: &[(&str, &str)]) -> Candidate {
        let mut d = descriptor(role, "x");
        d.tag = tag.map(str::to_owned);
        d.attributes = attrs(kv);
        Candidate {
            descriptor: d,
            evidence: CandidateEvidence {
                ax_widget_role: Some(role.to_owned()),
                native_semantics: false,
                aria_semantics: false,
                focusable: false,
                direct_listener: false,
                hover_listener: false,
                delegated_likelihood: 0.0,
                action_cursor: false,
                draggable: false,
                drop_zone: false,
                visible: true,
                enabled: true,
            },
            rung: Rung::Ax,
        }
    }

    use ActionKind::{
        Click, Drag, Hover, KeyboardActivate, Keys, Scroll, Select, SetChecked, SetRange, Type, Upload,
    };

    #[test]
    fn role_table() {
        let table: &[(&str, &[ActionKind])] = &[
            ("button", &[Click, KeyboardActivate]),
            ("link", &[Click, KeyboardActivate]),
            ("textbox", &[Type]),
            ("searchbox", &[Type]),
            ("checkbox", &[SetChecked]),
            ("switch", &[SetChecked]),
            ("radio", &[Click]),
            ("combobox", &[Select]),
            ("listbox", &[Select]),
            ("slider", &[SetRange]),
            ("spinbutton", &[SetRange]),
            ("tab", &[Click, Keys]),
            ("treeitem", &[Click, Keys]),
            ("menuitem", &[Click, Keys]),
            ("menuitemcheckbox", &[Click, Keys]),
            ("option", &[Click, KeyboardActivate]),
            ("disclosure", &[Click]),
            ("menu", &[Hover]),
            ("generic", &[]),
            ("heading", &[]),
        ];
        for (role, want) in table {
            assert_eq!(ActionVocabulary::for_role(role), *want, "{role}");
        }
    }

    #[test]
    fn candidate_refinements() {
        let v = |c: &Candidate| ActionVocabulary::for_candidate(c);
        assert_eq!(
            v(&cand("textbox", Some("input"), &[("type", "text")])),
            vec![Type]
        );
        assert_eq!(
            v(&cand("button", Some("input"), &[("type", "file")])),
            vec![Upload]
        );
        assert_eq!(v(&cand("combobox", Some("select"), &[])), vec![Select]);
        assert_eq!(
            v(&cand("combobox", Some("input"), &[("aria-autocomplete", "list")])),
            vec![Type, Select]
        );
        assert_eq!(
            v(&cand("button", Some("button"), &[("aria-expanded", "false")])),
            vec![Click, KeyboardActivate]
        );
        assert_eq!(
            v(&cand("generic", Some("div"), &[("aria-expanded", "true")])),
            vec![Click]
        );
        assert_eq!(
            v(&cand("button", Some("button"), &[("aria-haspopup", "menu")])),
            vec![Click, KeyboardActivate, Hover]
        );
        assert_eq!(
            v(&cand("button", Some("button"), &[("aria-haspopup", "false")])),
            vec![Click, KeyboardActivate]
        );
        assert_eq!(
            v(&cand("generic", Some("div"), &[("draggable", "true")])),
            vec![Drag]
        );
        assert_eq!(
            v(&cand("generic", Some("div"), &[("overflow-y", "auto")])),
            vec![Scroll]
        );
        assert_eq!(v(&cand("feed", Some("div"), &[])), vec![Scroll]);
        assert_eq!(
            v(&cand("slider", Some("input"), &[("type", "range")])),
            vec![SetRange]
        );
    }

    #[test]
    fn listener_only_generic_is_clickable() {
        let mut c = cand("generic", Some("div"), &[]);
        assert!(ActionVocabulary::for_candidate(&c).is_empty());
        c.evidence.direct_listener = true;
        assert_eq!(ActionVocabulary::for_candidate(&c), vec![Click]);
        c.evidence.focusable = true;
        assert_eq!(ActionVocabulary::for_candidate(&c), vec![Click, KeyboardActivate]);
    }

    #[test]
    fn hover_listener_only_generic_is_hoverable() {
        let mut c = cand("generic", Some("div"), &[]);
        c.evidence.hover_listener = true;
        assert_eq!(ActionVocabulary::for_candidate(&c), vec![Hover]);
        c.evidence.direct_listener = true;
        assert_eq!(ActionVocabulary::for_candidate(&c), vec![Click, Hover]);
    }
}
