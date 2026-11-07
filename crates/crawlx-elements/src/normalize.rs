//! Normalization feeding `ElementIdentityV1`.
//!
//! Everything volatile in an accessible name (counters, dates, relative
//! times, prices) is removed so that a control keeps its identity while its
//! content churns. Wrapper roles that carry no semantics are removed from the
//! ancestor path so that an extra `div` never changes a hash.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

/// Normalized names longer than this many characters are truncated.
pub const MAX_NAME_CHARS: usize = 120;
/// Container text is truncated to this many characters.
pub const MAX_CONTAINER_CHARS: usize = 50;
/// At most this many (innermost) stable ancestor roles enter an identity.
pub const MAX_ANCESTOR_ROLES: usize = 8;
/// Containers are searched this many stable ancestors up.
pub const MAX_CONTAINER_DEPTH: usize = 3;

const MONTH: &str = "(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";
const CURRENCY_SYMBOLS: &str = "$€£¥₹₩₽₺₫฿";
const CURRENCY_CODES: &str = "(?:usd|eur|gbp|jpy|cny|inr|cad|aud|chf|rub|krw|brl|mxn)";
const UNIT: &str =
    "(?:seconds?|secs?|minutes?|mins?|hours?|hrs?|days?|weeks?|wks?|months?|mos?|years?|yrs?|[smhdwy])";

fn pattern_sources() -> Vec<String> {
    vec![
        // currency amounts: symbol prefix, code prefix or suffix
        format!("[{CURRENCY_SYMBOLS}]\\s?\\d(?:[\\d,.]*\\d)?"),
        format!("\\b\\d(?:[\\d,.]*\\d)?\\s?{CURRENCY_CODES}\\b"),
        format!("\\b{CURRENCY_CODES}\\s?\\d(?:[\\d,.]*\\d)?"),
        // ISO date / datetime
        "\\b\\d{4}-\\d{1,2}-\\d{1,2}(?:[t ]\\d{1,2}:\\d{2}(?::\\d{2}(?:\\.\\d+)?)?(?:z|[+-]\\d{2}:?\\d{2})?)?".to_owned(),
        // 12/31/2026, 31.12.2026, 2026/12/31
        "\\b\\d{1,4}[/.]\\d{1,2}[/.]\\d{1,4}\\b".to_owned(),
        // Dec 5, 2026 / December 5th / Dec. 5
        format!("\\b{MONTH}\\.?\\s+\\d{{1,2}}(?:st|nd|rd|th)?(?:,?\\s+\\d{{4}})?\\b"),
        // 5 Dec 2026 / 5th of December
        format!("\\b\\d{{1,2}}(?:st|nd|rd|th)?\\s+(?:of\\s+)?{MONTH}\\.?(?:,?\\s+\\d{{4}})?\\b"),
        // December 2026
        format!("\\b{MONTH}\\.?,?\\s+\\d{{4}}\\b"),
        // 10:45, 10:45:12, 10:45 pm
        "\\b\\d{1,2}:\\d{2}(?::\\d{2})?(?:\\s?[ap]\\.?m\\b\\.?)?".to_owned(),
        // 3 min ago, 5m ago, an hour ago, in 2 days
        format!("\\b(?:in\\s+)?(?:\\d+|an?|one)\\s*{UNIT}\\s+ago\\b"),
        format!("\\bin\\s+\\d+\\s*{UNIT}\\b"),
        "\\byesterday\\b|\\bjust now\\b|\\b(?:a|an)\\s+(?:moment|few moments?|while)\\s+ago\\b".to_owned(),
    ]
}

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    pattern_sources()
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

static EMPTY_BRACKETS: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"[(\[{]\s*[)\]}]").ok());

/// Number of volatile-content patterns that compiled; equals
/// `pattern_sources().len()` unless a pattern is broken (asserted in tests).
#[must_use]
pub fn compiled_pattern_count() -> usize {
    PATTERNS.len()
}

/// Normalize an accessible name for identity: NFKC, lowercase, then strip
/// currency amounts, dates, times, relative times, digits and empty brackets,
/// and collapse whitespace runs. Idempotent.
#[must_use]
pub fn normalize_accessible_name(raw: &str) -> String {
    let mut cur: String = raw.nfkc().collect::<String>().to_lowercase();
    // Removing one volatile fragment can expose another ("a (1) day ago"), so iterate to a fixed point.
    for _ in 0..4 {
        let next = strip_volatile(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    truncate_chars(&cur, MAX_NAME_CHARS)
}

/// Locale-aware name normalization for V2, selected by page BCP-47 language.
/// Dates, relative times and grouped numbers are removed before V1 normalization.
#[must_use]
pub fn normalize_accessible_name_v2(raw: &str, lang: &str) -> String {
    crate::locale::normalize_name(raw, lang)
}

pub(crate) fn strip_standard_patterns(text: &str) -> String {
    let mut s = text.to_owned();
    for re in PATTERNS.iter() {
        s = re.replace_all(&s, " ").into_owned();
    }
    s
}

fn strip_volatile(text: &str) -> String {
    let s = strip_standard_patterns(text);
    let no_digits: String = s
        .chars()
        .filter(|c| !c.is_numeric() && !CURRENCY_SYMBOLS.contains(*c))
        .collect();
    let mut s = collapse_ws(&no_digits);
    if let Some(re) = EMPTY_BRACKETS.as_ref() {
        loop {
            let next = re.replace_all(&s, "").into_owned();
            if next == s {
                break;
            }
            s = next;
        }
    }
    collapse_ws(&s)
}

/// Collapse whitespace runs to one space and trim.
#[must_use]
pub fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Truncate to at most `max` characters (not bytes), then trim.
#[must_use]
pub fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].trim_end().to_owned(),
        None => s.to_owned(),
    }
}

/// Roles dropped from ancestor paths: they carry no semantics and frameworks
/// insert them freely.
const WRAPPER_ROLES: [&str; 10] = [
    "generic",
    "group",
    "none",
    "presentation",
    "div",
    "span",
    "body",
    "rootwebarea",
    "ignored",
    "genericcontainer",
];

/// Is `role` a semantics-free wrapper?
#[must_use]
pub fn is_wrapper_role(role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    r.is_empty() || WRAPPER_ROLES.contains(&r.as_str())
}

/// Ancestor roles (outermost first) with wrappers removed, lowercased, keeping
/// the innermost [`MAX_ANCESTOR_ROLES`].
#[must_use]
pub fn stable_ancestor_role_path(ancestor_roles: &[String]) -> Vec<String> {
    let stable: Vec<String> = ancestor_roles
        .iter()
        .filter(|r| !is_wrapper_role(r))
        .map(|r| r.trim().to_ascii_lowercase())
        .collect();
    let skip = stable.len().saturating_sub(MAX_ANCESTOR_ROLES);
    stable.into_iter().skip(skip).collect()
}

/// Landmark-like container roles whose *name* is stable and discriminating.
const LANDMARK_ROLES: [&str; 19] = [
    "banner",
    "navigation",
    "main",
    "complementary",
    "contentinfo",
    "search",
    "form",
    "region",
    "dialog",
    "alertdialog",
    "tabpanel",
    "menu",
    "menubar",
    "toolbar",
    "tablist",
    "table",
    "grid",
    "tree",
    "listbox",
];

/// Is `role` a landmark-like container (its name is part of the signature)?
#[must_use]
pub fn is_landmark_role(role: &str) -> bool {
    LANDMARK_ROLES.contains(&role.trim().to_ascii_lowercase().as_str())
}

/// Separator between the container role and its text in
/// `ObservedDescriptor::container_text`.
pub const CONTAINER_SEP: char = '|';

/// Encode the nearest named container into `ObservedDescriptor::container_text`
/// as `"{role}|{text}"` (text truncated to [`MAX_CONTAINER_CHARS`]).
#[must_use]
pub fn encode_container(role: &str, text: &str) -> String {
    format!(
        "{}{CONTAINER_SEP}{}",
        role.trim().to_ascii_lowercase(),
        truncate_chars(&collapse_ws(text), MAX_CONTAINER_CHARS)
    )
}

/// Container signature for identity (position-free).
///
/// A landmark container (`navigation`, `dialog`, `form`, named `region`, …)
/// contributes `"{role}:{normalized name}"`. An *instance* container (a card
/// heading, a row, a link) contributes only `"{role}"`, so every card of a
/// repeated template shares one signature and the item's own text never enters
/// identity. Text without a role prefix (built by another producer) is
/// normalized and used as is.
#[must_use]
pub fn container_signature(container_text: Option<&str>) -> Option<String> {
    let raw = container_text?.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.split_once(CONTAINER_SEP) {
        Some((role, text)) => {
            let role = role.trim().to_ascii_lowercase();
            if role.is_empty() {
                return None;
            }
            if is_landmark_role(&role) {
                let name = normalize_accessible_name(&truncate_chars(text, MAX_CONTAINER_CHARS));
                if name.is_empty() {
                    Some(role)
                } else {
                    Some(format!("{role}:{name}"))
                }
            } else {
                Some(role)
            }
        }
        None => {
            let n = normalize_accessible_name(&truncate_chars(raw, MAX_CONTAINER_CHARS));
            (!n.is_empty()).then_some(n)
        }
    }
}

const FORM_ROLES: [&str; 11] = [
    "textbox",
    "searchbox",
    "combobox",
    "listbox",
    "checkbox",
    "radio",
    "switch",
    "slider",
    "spinbutton",
    "option",
    "menuitemcheckbox",
];

/// Is the role/tag a form control (gets a `label_signature`)?
#[must_use]
pub fn is_form_control(role: &str, tag: Option<&str>) -> bool {
    let role = role.to_ascii_lowercase();
    FORM_ROLES.contains(&role.as_str())
        || matches!(
            tag.map(str::to_ascii_lowercase).as_deref(),
            Some("input" | "select" | "textarea")
        )
}

/// Label signature of a form control: the first available of `aria-label`,
/// `placeholder`, `name`, `title`, normalized. `None` for non-form controls or
/// when the page offers no label evidence beyond the accessible name.
#[must_use]
pub fn label_signature(
    role: &str,
    tag: Option<&str>,
    attributes: &BTreeMap<String, String>,
) -> Option<String> {
    if !is_form_control(role, tag) {
        return None;
    }
    ["aria-label", "placeholder", "name", "title"]
        .iter()
        .filter_map(|k| attributes.get(*k))
        .map(|v| normalize_accessible_name(v))
        .find(|v| !v.is_empty())
}

/// `type`/`inputmode`/role refinement of a control.
///
/// Native `input` → its `type` (default `text`) plus `/inputmode`; `button` →
/// its `type` when present; `select` → `select` or `select-multiple`;
/// `textarea`; `contenteditable`; otherwise an explicit `role` attribute on a
/// non-native element as `role:{value}`.
#[must_use]
pub fn control_type(tag: Option<&str>, attributes: &BTreeMap<String, String>) -> Option<String> {
    let tag = tag.map(str::to_ascii_lowercase);
    let attr = |k: &str| attributes.get(k).map(|v| v.trim().to_ascii_lowercase());
    match tag.as_deref() {
        Some("input") => {
            let ty = attr("type")
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| "text".to_owned());
            Some(match attr("inputmode").filter(|m| !m.is_empty()) {
                Some(mode) => format!("{ty}/{mode}"),
                None => ty,
            })
        }
        Some("button") => attr("type").filter(|t| !t.is_empty()),
        Some("select") => Some(if attributes.contains_key("multiple") {
            "select-multiple".to_owned()
        } else {
            "select".to_owned()
        }),
        Some("textarea") => Some("textarea".to_owned()),
        _ => {
            if attr("contenteditable").is_some_and(|v| v != "false") {
                return Some("contenteditable".to_owned());
            }
            let native = matches!(tag.as_deref(), Some("a" | "area" | "summary" | "option"));
            if native {
                return None;
            }
            attr("role")
                .and_then(|r| r.split_whitespace().next().map(str::to_owned))
                .map(|r| format!("role:{r}"))
        }
    }
}

/// Normalize a durable attribute value (`id`, `data-testid`, …) for
/// comparison: lowercase, digits and punctuation runs that frameworks
/// randomize removed from the numeric part.
#[must_use]
pub fn normalize_attr_value(raw: &str) -> String {
    let lower = raw.nfkc().collect::<String>().to_lowercase();
    let no_digits: String = lower.chars().filter(|c| !c.is_numeric()).collect();
    collapse_ws(&no_digits)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn all_patterns_compile() {
        assert_eq!(compiled_pattern_count(), pattern_sources().len());
        assert!(EMPTY_BRACKETS.is_some());
    }

    #[test]
    fn normalization_table() {
        let cases: &[(&str, &str)] = &[
            // counters
            ("Cart (3)", "cart"),
            ("Cart (12)", "cart"),
            ("Inbox  [ 7 ]", "inbox"),
            ("3 comments", "comments"),
            ("Page 4 of 10", "page of"),
            // ISO / slash / month-name dates
            ("Due 2026-12-31", "due"),
            ("Created 2026-12-31T10:45:12Z", "created"),
            ("Updated 12/31/2026", "updated"),
            ("Updated 31.12.2026", "updated"),
            ("Posted Dec 5, 2026", "posted"),
            ("Posted December 5th", "posted"),
            ("Posted 5 Dec 2026", "posted"),
            ("Report December 2026", "report"),
            ("Meeting at 10:45 pm", "meeting at"),
            // relative times
            ("Reply 3 min ago", "reply"),
            ("Reply 5m ago", "reply"),
            ("Edited an hour ago", "edited"),
            ("Edited yesterday", "edited"),
            ("Seen just now", "seen"),
            ("Starts in 2 days", "starts"),
            // currency
            ("Buy for $19.99", "buy for"),
            ("Buy for €1,299.00", "buy for"),
            ("Pay 20 USD", "pay"),
            ("Pay USD 20.5", "pay"),
            // whitespace, case, NFKC
            ("  Save\t\n  changes  ", "save changes"),
            ("ＳＡＶＥ １２", "save"),
            // words containing month abbreviations survive
            ("May I help", "may i help"),
            ("Market", "market"),
        ];
        for (raw, want) in cases {
            assert_eq!(normalize_accessible_name(raw), *want, "input {raw:?}");
        }
    }

    #[test]
    fn truncates_long_names() {
        let long = "word ".repeat(100);
        assert!(normalize_accessible_name(&long).chars().count() <= MAX_NAME_CHARS);
    }

    #[test]
    fn ancestor_path_drops_wrappers() {
        let roles: Vec<String> = [
            "RootWebArea",
            "generic",
            "main",
            "div",
            "list",
            "group",
            "listitem",
            "none",
            "span",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(
            stable_ancestor_role_path(&roles),
            vec!["main", "list", "listitem"]
        );
    }

    #[test]
    fn ancestor_path_keeps_innermost() {
        let roles: Vec<String> = (b'a'..b'a' + 20).map(|c| format!("r{}", char::from(c))).collect();
        let p = stable_ancestor_role_path(&roles);
        assert_eq!(p.len(), MAX_ANCESTOR_ROLES);
        assert_eq!(p.last().map(String::as_str), Some("rt"));
    }

    #[test]
    fn container_signature_templates_instances() {
        // landmark names are kept, instance names are not
        assert_eq!(
            container_signature(Some(&encode_container("dialog", "Settings 2"))),
            Some("dialog:settings".to_owned())
        );
        assert_eq!(
            container_signature(Some(&encode_container("heading", "Blue Widget"))),
            Some("heading".to_owned())
        );
        assert_eq!(
            container_signature(Some(&encode_container("heading", "Red Widget"))),
            Some("heading".to_owned())
        );
        assert_eq!(
            container_signature(Some("Plain Title 3")),
            Some("plain title".to_owned())
        );
        assert_eq!(container_signature(None), None);
        assert_eq!(container_signature(Some("  ")), None);
    }

    #[test]
    fn encode_container_truncates() {
        let enc = encode_container("region", &"x".repeat(200));
        assert_eq!(enc.chars().count(), "region|".len() + MAX_CONTAINER_CHARS);
    }

    #[test]
    fn control_types() {
        let attrs = |kv: &[(&str, &str)]| -> BTreeMap<String, String> {
            kv.iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert_eq!(control_type(Some("input"), &attrs(&[])), Some("text".into()));
        assert_eq!(
            control_type(Some("INPUT"), &attrs(&[("type", "Email")])),
            Some("email".into())
        );
        assert_eq!(
            control_type(
                Some("input"),
                &attrs(&[("type", "text"), ("inputmode", "numeric")])
            ),
            Some("text/numeric".into())
        );
        assert_eq!(
            control_type(Some("button"), &attrs(&[("type", "submit")])),
            Some("submit".into())
        );
        assert_eq!(control_type(Some("button"), &attrs(&[])), None);
        assert_eq!(
            control_type(Some("select"), &attrs(&[("multiple", "")])),
            Some("select-multiple".into())
        );
        assert_eq!(
            control_type(Some("textarea"), &attrs(&[])),
            Some("textarea".into())
        );
        assert_eq!(
            control_type(Some("div"), &attrs(&[("role", "Tab extra")])),
            Some("role:tab".into())
        );
        assert_eq!(
            control_type(Some("div"), &attrs(&[("contenteditable", "true")])),
            Some("contenteditable".into())
        );
        assert_eq!(control_type(Some("a"), &attrs(&[("href", "/x")])), None);
        assert_eq!(control_type(Some("div"), &attrs(&[])), None);
    }

    #[test]
    fn label_signatures() {
        let mut a = BTreeMap::new();
        a.insert("placeholder".to_owned(), "Search 100 items".to_owned());
        assert_eq!(
            label_signature("searchbox", Some("input"), &a),
            Some("search items".to_owned())
        );
        assert_eq!(label_signature("button", Some("button"), &a), None);
        assert_eq!(label_signature("textbox", Some("input"), &BTreeMap::new()), None);
    }

    #[test]
    fn attr_values() {
        assert_eq!(normalize_attr_value("Row-17-Delete"), "row--delete");
        assert_eq!(
            normalize_attr_value("headlessui-menu-button-:r1:"),
            "headlessui-menu-button-:r:"
        );
    }

    proptest! {
        #[test]
        fn normalization_is_idempotent(s in "[a-zA-Z0-9 ()$:/.,-]{0,60}") {
            let once = normalize_accessible_name(&s);
            prop_assert_eq!(normalize_accessible_name(&once), once);
        }

        #[test]
        fn counters_never_change_the_name(n in 0u32..100_000, m in 0u32..100_000) {
            prop_assert_eq!(
                normalize_accessible_name(&format!("Notifications ({n})")),
                normalize_accessible_name(&format!("Notifications ({m})"))
            );
        }
    }
}
