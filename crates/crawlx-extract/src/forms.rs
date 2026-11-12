//! Static form extraction (`pages.forms[]`, compatibility flag `-fx`).
//!
//! Shapes ported from an MIT-licensed upstream (see THIRD_PARTY_NOTICES.md;
//! `ParseFormFields` and `Form`), extended with per-control type, value, `required` and
//! `<select>` options so the static plane exposes what the browser plane's
//! form semantics would see.

use scraper::{ElementRef, Html};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::dom::{collapse_ws, walk};
use crate::metadata::effective_base;

/// Cap on controls kept per form.
pub const MAX_INPUTS_PER_FORM: usize = 256;
/// Cap on `<option>` values kept per select.
pub const MAX_OPTIONS_PER_SELECT: usize = 256;
/// Cap on forms kept per document.
pub const MAX_FORMS: usize = 512;

/// One form control (`input`, `select`, `textarea`) with a `name`.
///
/// Besides the identity (`name`, `kind`, `value`, `required`, `options`) the
/// constraint attributes that decide which value a submission may carry are
/// kept (`pattern`, `maxlength`, `min`, `max`, ...); they feed
/// [`crate::form_fill`] and [`crate::kb::classify_form`] and are omitted from
/// the JSON form when absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticInput {
    /// `name` attribute.
    pub name: String,
    /// `input type` (lower-case, default `text`), `select` or `textarea`.
    pub kind: String,
    /// `value` attribute (inputs), selected/first option (selects) or text (textareas).
    pub value: Option<String>,
    /// `required` attribute present.
    pub required: bool,
    /// `<option>` values of a select, in document order.
    pub options: Vec<String>,
    /// `id` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `placeholder` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// `autocomplete` attribute (autofill token list, as written).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autocomplete: Option<String>,
    /// `pattern` attribute (the browser anchors it to the whole value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// `min` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    /// `max` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
    /// `step` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// `maxlength` attribute, when a non-negative integer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maxlength: Option<usize>,
    /// `minlength` attribute, when a non-negative integer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minlength: Option<usize>,
    /// `checked` attribute present (checkboxes and radios).
    #[serde(default, skip_serializing_if = "is_false")]
    pub checked: bool,
    /// `disabled` attribute present: a browser would not submit the control.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
}

// serde `skip_serializing_if` predicates take a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// A form found in static HTML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticForm {
    /// Absolute action URL (the page URL when `action` is absent).
    pub action: Url,
    /// Upper-case method (`GET` by default).
    pub method: String,
    /// `enctype`; defaults to `application/x-www-form-urlencoded` for non-GET forms, absent for GET.
    pub enctype: Option<String>,
    /// Named controls in document order.
    pub inputs: Vec<StaticInput>,
    /// Labels of submit controls (`button`, `input[type=submit|image]`).
    pub submit_labels: Vec<String>,
}

/// Extract forms from an HTML string fetched from `page`.
///
/// # Errors
/// [`crate::ExtractError::ParseMemory`] when the process-wide parse-memory budget is exhausted.
pub fn extract_str(html: &str, page: &Url) -> Result<Vec<StaticForm>, crate::ExtractError> {
    // declared before `doc`: released after the parsed tree is dropped
    let mut charge = crate::parse_budget::charge(html.len())?;
    let doc = crate::dom::parse_document(&mut charge, html)?;
    let base = effective_base(&doc, page);
    Ok(extract(&doc, &base))
}

/// Extract forms from a parsed document, resolving actions against `base`.
#[must_use]
pub fn extract(doc: &Html, base: &Url) -> Vec<StaticForm> {
    let mut forms = Vec::new();
    walk(doc.tree.root(), |el| {
        if forms.len() >= MAX_FORMS {
            return false;
        }
        if el.value().name() == "form" {
            if let Some(f) = form(el, base) {
                forms.push(f);
            }
            return false;
        }
        true
    });
    forms
}

fn form(el: ElementRef<'_>, base: &Url) -> Option<StaticForm> {
    let v = el.value();
    let action_raw = v.attr("action").unwrap_or("").trim();
    let mut action = base.join(action_raw).ok()?;
    if !matches!(action.scheme(), "http" | "https") {
        return None;
    }
    action.set_fragment(None);
    let method = v
        .attr("method")
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let enctype = match v.attr("enctype").map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => Some(e.to_owned()),
        None if method != "GET" => Some("application/x-www-form-urlencoded".to_owned()),
        None => None,
    };

    let mut inputs = Vec::new();
    let mut submit_labels = Vec::new();
    walk(*el, |c| {
        if c == el {
            return true;
        }
        let cv = c.value();
        match cv.name() {
            "input" | "select" | "textarea" => {
                if inputs.len() < MAX_INPUTS_PER_FORM {
                    inputs.extend(control(c));
                }
                if cv.name() == "input"
                    && cv
                        .attr("type")
                        .is_some_and(|t| t.eq_ignore_ascii_case("submit") || t.eq_ignore_ascii_case("image"))
                {
                    let label = cv.attr("value").or_else(|| cv.attr("alt")).unwrap_or("").trim();
                    if !label.is_empty() {
                        submit_labels.push(label.to_owned());
                    }
                }
                cv.name() != "select"
            }
            "button" => {
                let is_submit = cv.attr("type").is_none_or(|t| t.eq_ignore_ascii_case("submit"));
                if is_submit {
                    let text = collapse_ws(&c.text().collect::<String>());
                    let label = if text.is_empty() {
                        cv.attr("value")
                            .or_else(|| cv.attr("aria-label"))
                            .unwrap_or("")
                            .trim()
                            .to_owned()
                    } else {
                        text
                    };
                    if !label.is_empty() {
                        submit_labels.push(label);
                    }
                }
                false
            }
            _ => true,
        }
    });

    Some(StaticForm {
        action,
        method,
        enctype,
        inputs,
        submit_labels,
    })
}

fn control(el: ElementRef<'_>) -> Option<StaticInput> {
    let v = el.value();
    let name = v
        .attr("name")
        .map(str::trim)
        .filter(|n| !n.is_empty())?
        .to_owned();
    let required = v.attr("required").is_some();
    let mut input = match v.name() {
        "input" => StaticInput {
            name,
            kind: v.attr("type").map_or("text", str::trim).to_ascii_lowercase(),
            value: v.attr("value").map(str::to_owned),
            required,
            ..StaticInput::default()
        },
        "select" => {
            let mut options = Vec::new();
            let mut selected: Option<String> = None;
            walk(*el, |o| {
                if o.value().name() == "option" && options.len() < MAX_OPTIONS_PER_SELECT {
                    let val = o
                        .value()
                        .attr("value")
                        .map_or_else(|| collapse_ws(&o.text().collect::<String>()), str::to_owned);
                    if o.value().attr("selected").is_some() && selected.is_none() {
                        selected = Some(val.clone());
                    }
                    options.push(val);
                }
                true
            });
            let value = selected.or_else(|| options.first().cloned());
            StaticInput {
                name,
                kind: "select".to_owned(),
                value,
                required,
                options,
                ..StaticInput::default()
            }
        }
        "textarea" => {
            let text = el.text().collect::<String>();
            StaticInput {
                name,
                kind: "textarea".to_owned(),
                value: (!text.trim().is_empty()).then(|| text.trim().to_owned()),
                required,
                ..StaticInput::default()
            }
        }
        _ => return None,
    };
    let attr = |key: &str| {
        v.attr(key)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    input.id = attr("id");
    input.placeholder = attr("placeholder");
    input.autocomplete = attr("autocomplete");
    input.pattern = v.attr("pattern").filter(|p| !p.is_empty()).map(str::to_owned);
    input.min = attr("min");
    input.max = attr("max");
    input.step = attr("step");
    input.maxlength = attr("maxlength").and_then(|n| n.parse().ok());
    input.minlength = attr("minlength").and_then(|n| n.parse().ok());
    input.checked = v.attr("checked").is_some();
    input.disabled = v.attr("disabled").is_some();
    Some(input)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn login_form_shape() {
        let html = r#"<form action="/login" method="post">
            <input name="user" type="text" required>
            <input name="pass" type="password">
            <select name="role"><option value="a">A</option><option value="b" selected>B</option></select>
            <textarea name="note">hi</textarea>
            <input type="hidden" name="csrf" value="tok">
            <input type="submit" value="Sign in">
            <button>Go</button>
        </form>"#;
        let forms = extract_str(html, &Url::parse("https://example.com/x/").unwrap()).unwrap();
        assert_eq!(forms.len(), 1);
        let f = &forms[0];
        assert_eq!(f.action.as_str(), "https://example.com/login");
        assert_eq!(f.method, "POST");
        assert_eq!(f.enctype.as_deref(), Some("application/x-www-form-urlencoded"));
        assert_eq!(f.inputs.len(), 5);
        assert!(f.inputs[0].required);
        assert_eq!(f.inputs[2].value.as_deref(), Some("b"));
        assert_eq!(f.inputs[2].options, vec!["a", "b"]);
        assert_eq!(f.inputs[3].value.as_deref(), Some("hi"));
        assert_eq!(f.inputs[4].value.as_deref(), Some("tok"));
        assert_eq!(f.submit_labels, vec!["Sign in", "Go"]);
    }

    #[test]
    fn get_form_without_action_points_at_page() {
        let forms = extract_str(
            "<form><input name=q></form>",
            &Url::parse("https://example.com/search#frag").unwrap(),
        )
        .unwrap();
        assert_eq!(forms[0].action.as_str(), "https://example.com/search");
        assert_eq!(forms[0].method, "GET");
        assert!(forms[0].enctype.is_none());
    }
}
