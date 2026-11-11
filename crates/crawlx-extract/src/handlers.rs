//! Typed text and attribute handlers with deterministic, recipe-identical projections.
//!
//! [`TextHandler`] / [`TextHandlers`] wrap extracted strings and offer the cleaning, safe-regex,
//! JSON-parse and list projections that item recipes apply as transforms; [`AttributesHandler`]
//! wraps one element's attributes. Every method delegates to the same free functions the
//! recipe transforms use ([`clean_text`], [`parse_json`], [`regex_values`], [`attribute_object`]),
//! so a handler chain and the equivalent recipe produce identical output. All inputs and results
//! are bounded and nothing here performs I/O. There is no promise of a foreign object model.

use std::collections::BTreeMap;

use regex::Regex;
use scraper::ElementRef;
use serde_json::Value;

use crate::regex_builtins::{self, RegexError};

/// Largest string parsed as JSON, in bytes.
pub const MAX_JSON_BYTES: usize = 1 << 20;
/// Most items a handler list holds or returns.
pub const MAX_ITEMS: usize = 10_000;
/// Most attributes read from one element.
pub const MAX_ATTRIBUTES: usize = 1_024;

/// Why a handler operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandlerError {
    /// The string is not valid JSON within the depth limit.
    #[error("invalid json: {0}")]
    Json(String),
    /// The JSON string is longer than [`MAX_JSON_BYTES`].
    #[error("json input of {len} bytes exceeds {MAX_JSON_BYTES}")]
    JsonTooLarge {
        /// Input length in bytes.
        len: usize,
    },
    /// A list would exceed [`MAX_ITEMS`].
    #[error("handler list exceeds {MAX_ITEMS} items")]
    TooManyItems,
    /// A pattern was refused by the regex admission gate.
    #[error(transparent)]
    Regex(#[from] RegexError),
}

/// Collapse whitespace runs to one space, drop control and zero-width characters, trim edges.
#[must_use]
pub fn clean_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            pending_space = true;
        } else if c.is_control() || matches!(c, '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}' | '\u{ad}')
        {
            continue;
        } else {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push(c);
        }
    }
    out
}

/// Parse `text` as JSON.
///
/// # Errors
/// [`HandlerError::JsonTooLarge`] above [`MAX_JSON_BYTES`], [`HandlerError::Json`] for invalid
/// syntax or nesting deeper than the parser's recursion limit.
pub fn parse_json(text: &str) -> Result<Value, HandlerError> {
    if text.len() > MAX_JSON_BYTES {
        return Err(HandlerError::JsonTooLarge { len: text.len() });
    }
    serde_json::from_str(text).map_err(|e| {
        // Category and position only; the message of the parser can echo input text.
        HandlerError::Json(format!(
            "{:?} at line {} column {}",
            e.classify(),
            e.line(),
            e.column()
        ))
    })
}

/// Values of one capture `group` of `regex` in `text`: the first match, or every match when `all`.
#[must_use]
pub fn regex_values(regex: &Regex, group: usize, text: &str, all: bool) -> Vec<String> {
    let mut out = Vec::new();
    for caps in regex.captures_iter(text) {
        if let Some(found) = caps.get(group) {
            out.push(found.as_str().to_owned());
            if !all || out.len() >= MAX_ITEMS {
                break;
            }
        }
    }
    out
}

/// Attributes of `element` as a sorted name to value map, at most [`MAX_ATTRIBUTES`] entries.
#[must_use]
pub fn attribute_object(element: ElementRef<'_>) -> serde_json::Map<String, Value> {
    element
        .value()
        .attrs()
        .take(MAX_ATTRIBUTES)
        .map(|(name, value)| (name.to_owned(), Value::String(value.to_owned())))
        .collect()
}

/// One extracted string with deterministic projections.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TextHandler(String);

impl TextHandler {
    /// Wrap a string.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// Borrow the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Take the text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Cleaned copy, identical to the `clean` recipe transform.
    #[must_use]
    pub fn clean(&self) -> Self {
        Self(clean_text(&self.0))
    }

    /// Lines split on `\n`, with a trailing carriage return removed from each.
    ///
    /// # Errors
    /// [`HandlerError::TooManyItems`] above [`MAX_ITEMS`] lines.
    pub fn lines(&self) -> Result<TextHandlers, HandlerError> {
        TextHandlers::from_strings(
            self.0
                .split('\n')
                .map(|l| l.strip_suffix('\r').unwrap_or(l).to_owned()),
        )
    }

    /// Every match of `pattern` (capture `group`), identical to the `regex` transform with `all`.
    ///
    /// # Errors
    /// [`HandlerError::Regex`] when the pattern fails admission or `group` is out of range.
    pub fn regex(&self, pattern: &str, group: usize) -> Result<TextHandlers, HandlerError> {
        let regex = admit(pattern, group)?;
        TextHandlers::from_strings(regex_values(&regex, group, &self.0, true))
    }

    /// First match of `pattern`, identical to the `regex` transform without `all`.
    ///
    /// # Errors
    /// [`HandlerError::Regex`] when the pattern fails admission or `group` is out of range.
    pub fn regex_first(&self, pattern: &str, group: usize) -> Result<Option<Self>, HandlerError> {
        let regex = admit(pattern, group)?;
        Ok(regex_values(&regex, group, &self.0, false).pop().map(Self))
    }

    /// Every match of a built-in pattern (bare or versioned name).
    ///
    /// # Errors
    /// [`HandlerError::Regex`] for an unknown name.
    pub fn builtin(&self, name: &str) -> Result<TextHandlers, HandlerError> {
        let found = regex_builtins::builtin(name)?;
        let regex = regex_builtins::compile_regex(found.pattern)?;
        TextHandlers::from_strings(regex_values(&regex, found.group, &self.0, true))
    }

    /// Parse as JSON, identical to the `json_parse` recipe transform.
    ///
    /// # Errors
    /// [`HandlerError::Json`] or [`HandlerError::JsonTooLarge`].
    pub fn json(&self) -> Result<Value, HandlerError> {
        parse_json(&self.0)
    }
}

impl AsRef<str> for TextHandler {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn admit(pattern: &str, group: usize) -> Result<Regex, HandlerError> {
    let regex = regex_builtins::compile_regex(pattern)?;
    let groups = regex.captures_len().saturating_sub(1);
    if group > groups {
        return Err(RegexError::GroupOutOfRange { group, groups }.into());
    }
    Ok(regex)
}

/// An ordered list of extracted strings with deterministic list projections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextHandlers(Vec<TextHandler>);

impl TextHandlers {
    /// Wrap strings in order.
    ///
    /// # Errors
    /// [`HandlerError::TooManyItems`] above [`MAX_ITEMS`].
    pub fn from_strings<I: IntoIterator<Item = String>>(items: I) -> Result<Self, HandlerError> {
        let mut out = Vec::new();
        for item in items {
            if out.len() >= MAX_ITEMS {
                return Err(HandlerError::TooManyItems);
            }
            out.push(TextHandler(item));
        }
        Ok(Self(out))
    }

    /// Number of items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Item at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&TextHandler> {
        self.0.get(index)
    }

    /// First item.
    #[must_use]
    pub fn first(&self) -> Option<&TextHandler> {
        self.0.first()
    }

    /// Last item.
    #[must_use]
    pub fn last(&self) -> Option<&TextHandler> {
        self.0.last()
    }

    /// Iterate in order.
    pub fn iter(&self) -> std::slice::Iter<'_, TextHandler> {
        self.0.iter()
    }

    /// At most the first `count` items, identical to the `limit` recipe transform.
    #[must_use]
    pub fn limit(&self, count: usize) -> Self {
        Self(self.0.iter().take(count).cloned().collect())
    }

    /// Every item cleaned.
    #[must_use]
    pub fn clean(&self) -> Self {
        Self(self.0.iter().map(TextHandler::clean).collect())
    }

    /// First occurrence of each distinct item, in order, identical to the `dedupe` transform.
    #[must_use]
    pub fn dedupe(&self) -> Self {
        let mut seen = std::collections::BTreeSet::new();
        Self(
            self.0
                .iter()
                .filter(|t| seen.insert(t.as_str()))
                .cloned()
                .collect(),
        )
    }

    /// Every match of `pattern` across all items, in item then match order.
    ///
    /// # Errors
    /// [`HandlerError::Regex`] on admission failure, [`HandlerError::TooManyItems`] on overflow.
    pub fn regex(&self, pattern: &str, group: usize) -> Result<Self, HandlerError> {
        let regex = admit(pattern, group)?;
        Self::from_strings(
            self.0
                .iter()
                .flat_map(|t| regex_values(&regex, group, t.as_str(), true)),
        )
    }

    /// First match of `pattern` in each item; items without a match are dropped.
    ///
    /// # Errors
    /// [`HandlerError::Regex`] on admission failure.
    pub fn regex_first(&self, pattern: &str, group: usize) -> Result<Self, HandlerError> {
        let regex = admit(pattern, group)?;
        Self::from_strings(
            self.0
                .iter()
                .filter_map(|t| regex_values(&regex, group, t.as_str(), false).pop()),
        )
    }

    /// Parse every item as JSON.
    ///
    /// # Errors
    /// The first [`HandlerError::Json`] or [`HandlerError::JsonTooLarge`].
    pub fn json(&self) -> Result<Vec<Value>, HandlerError> {
        self.0.iter().map(TextHandler::json).collect()
    }

    /// Items joined with `separator`, identical to the `join` recipe transform.
    #[must_use]
    pub fn join(&self, separator: &str) -> TextHandler {
        TextHandler(
            self.0
                .iter()
                .map(TextHandler::as_str)
                .collect::<Vec<_>>()
                .join(separator),
        )
    }

    /// JSON array of strings, the shape a many-valued recipe field emits.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Array(self.0.iter().map(|t| Value::String(t.0.clone())).collect())
    }
}

impl<'a> IntoIterator for &'a TextHandlers {
    type Item = &'a TextHandler;
    type IntoIter = std::slice::Iter<'a, TextHandler>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// One element's attributes as a sorted name to value map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributesHandler(BTreeMap<String, String>);

impl AttributesHandler {
    /// Read the attributes of `element`, at most [`MAX_ATTRIBUTES`].
    #[must_use]
    pub fn from_element(element: ElementRef<'_>) -> Self {
        Self(
            element
                .value()
                .attrs()
                .take(MAX_ATTRIBUTES)
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        )
    }

    /// Number of attributes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the element has no attributes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Value of `name`, matched ASCII case-insensitively.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<TextHandler> {
        self.0
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| TextHandler::new(value.as_str()))
    }

    /// Attribute names in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Attributes whose name starts with `prefix` (for example `data-`), as a new handler.
    #[must_use]
    pub fn with_prefix(&self, prefix: &str) -> Self {
        Self(
            self.0
                .iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        )
    }

    /// Names of attributes whose value contains `needle`, sorted.
    #[must_use]
    pub fn names_with_value(&self, needle: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(_, value)| value.contains(needle))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Parse the value of `name` as JSON.
    ///
    /// # Errors
    /// [`HandlerError::Json`] or [`HandlerError::JsonTooLarge`]; `Ok(None)` when absent.
    pub fn json(&self, name: &str) -> Result<Option<Value>, HandlerError> {
        self.get(name).map(|value| value.json()).transpose()
    }

    /// JSON object, identical to the `attributes` recipe projection.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(name, value)| (name.clone(), Value::String(value.clone())))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use scraper::{Html, Selector};

    #[test]
    fn clean_collapses_whitespace_and_drops_invisible_characters() {
        assert_eq!(clean_text("  a \t\n b\u{200b}c\u{feff}  d\u{0}  "), "a bc d");
        assert_eq!(clean_text("\u{a0}\u{3000}"), "");
        assert_eq!(TextHandler::new(" x  y ").clean().as_str(), "x y");
    }

    #[test]
    fn regex_projections_match_group_and_first_versus_all() {
        let text = TextHandler::new("a1 b22 c333");
        assert_eq!(
            text.regex(r"[a-z](\d+)", 1)
                .unwrap()
                .iter()
                .map(TextHandler::as_str)
                .collect::<Vec<_>>(),
            ["1", "22", "333"]
        );
        assert_eq!(text.regex_first(r"[a-z](\d+)", 1).unwrap().unwrap().as_str(), "1");
        assert!(text.regex_first("zzz", 0).unwrap().is_none());
        assert!(matches!(
            text.regex(r"(a)\1", 0),
            Err(HandlerError::Regex(RegexError::Backreference))
        ));
        assert!(matches!(
            text.regex("(a)", 3),
            Err(HandlerError::Regex(RegexError::GroupOutOfRange { .. }))
        ));
        assert_eq!(text.builtin("number").unwrap().len(), 3);
    }

    #[test]
    fn list_projections_are_ordered_and_bounded() {
        let list = TextHandlers::from_strings(["b", "a", "b", "c"].map(String::from)).unwrap();
        assert_eq!(list.first().unwrap().as_str(), "b");
        assert_eq!(list.last().unwrap().as_str(), "c");
        assert_eq!(list.dedupe().to_value(), serde_json::json!(["b", "a", "c"]));
        assert_eq!(list.limit(2).join("+").as_str(), "b+a");
        assert_eq!(list.regex_first("[ab]", 0).unwrap().len(), 3);
        assert!(matches!(
            TextHandlers::from_strings((0..=MAX_ITEMS).map(|i| i.to_string())),
            Err(HandlerError::TooManyItems)
        ));
    }

    #[test]
    fn json_is_bounded_and_errors_do_not_echo_input() {
        assert_eq!(
            TextHandler::new(r#"{"a":[1,2]}"#).json().unwrap(),
            serde_json::json!({"a":[1,2]})
        );
        let err = TextHandler::new("{secret-token").json().unwrap_err().to_string();
        assert!(!err.contains("secret-token"), "{err}");
        assert!(matches!(
            TextHandler::new("x".repeat(MAX_JSON_BYTES + 1)).json(),
            Err(HandlerError::JsonTooLarge { .. })
        ));
        assert!(TextHandler::new("[".repeat(1000)).json().is_err());
    }

    #[test]
    fn attributes_handler_projects_a_sorted_map() {
        let html = Html::parse_fragment(r#"<a id="x" data-b="2" data-a='{"k":1}' href="/p?id=7">t</a>"#);
        let a = html.select(&Selector::parse("a").unwrap()).next().unwrap();
        let attrs = AttributesHandler::from_element(a);
        assert_eq!(attrs.len(), 4);
        assert_eq!(
            attrs.names().collect::<Vec<_>>(),
            ["data-a", "data-b", "href", "id"]
        );
        assert_eq!(attrs.get("HREF").unwrap().as_str(), "/p?id=7");
        assert_eq!(attrs.with_prefix("data-").len(), 2);
        assert_eq!(attrs.names_with_value("id="), ["href"]);
        assert_eq!(attrs.json("data-a").unwrap().unwrap(), serde_json::json!({"k":1}));
        assert!(attrs.json("missing").unwrap().is_none());
        assert_eq!(attrs.to_value(), Value::Object(attribute_object(a)),);
    }
}
