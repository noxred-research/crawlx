//! Output templates (the `-output-template '{{email}} - {{url}}'` compatibility flag).
//!
//! The reference tool (an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md)
//! expands `{{tag}}` through a template engine with the last value of each field. Here a
//! template renders the cross product of its fields' values: a multi-valued field yields one
//! line per value and a field without a value yields no line at all, so templates compose
//! with multi-valued fields such as `key` or custom regex fields.

use super::fields::{self, Field, FieldError};
use crawlx_core::repo::PageRecord;
use serde_json::Value;
use thiserror::Error;
use url::Url;

/// Upper bound on the lines one template renders for one page (cross-product guard).
pub const MAX_LINES_PER_PAGE: usize = 10_000;

/// A malformed template.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TemplateError {
    /// A `{{` without its closing `}}`.
    #[error("unterminated `{{{{` at byte {offset}")]
    Unterminated {
        /// Byte offset of the opening braces.
        offset: usize,
    },
    /// A `{{name}}` that is neither a built-in field nor a valid custom field name.
    #[error("unknown template field")]
    UnknownField(#[from] FieldError),
    /// The template is empty.
    #[error("template is empty")]
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Literal(String),
    Field(Field),
}

/// A parsed output template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    source: String,
    parts: Vec<Part>,
}

impl Template {
    /// Parse `{{field}}` placeholders out of `source`.
    ///
    /// # Errors
    /// [`TemplateError::Empty`] for an empty source, [`TemplateError::Unterminated`] for an
    /// unclosed `{{`, [`TemplateError::UnknownField`] for a placeholder that is not a field name.
    pub fn parse(source: &str) -> Result<Self, TemplateError> {
        if source.is_empty() {
            return Err(TemplateError::Empty);
        }
        let mut parts = Vec::new();
        let mut rest = source;
        let mut offset = 0usize;
        while !rest.is_empty() {
            match rest.find("{{") {
                None => {
                    parts.push(Part::Literal(rest.to_owned()));
                    break;
                }
                Some(open) => {
                    if open > 0 {
                        parts.push(Part::Literal(rest[..open].to_owned()));
                    }
                    let after = &rest[open.saturating_add(2)..];
                    let close = after.find("}}").ok_or(TemplateError::Unterminated {
                        offset: offset.saturating_add(open),
                    })?;
                    let name = &after[..close];
                    parts.push(Part::Field(name.parse()?));
                    let consumed = open.saturating_add(2).saturating_add(close).saturating_add(2);
                    offset = offset.saturating_add(consumed);
                    rest = &rest[consumed..];
                }
            }
        }
        Ok(Self {
            source: source.to_owned(),
            parts,
        })
    }

    /// The template text as given.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Fields referenced by the template, in order of first appearance.
    #[must_use]
    pub fn fields(&self) -> Vec<&Field> {
        let mut out: Vec<&Field> = Vec::new();
        for p in &self.parts {
            if let Part::Field(f) = p {
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }
        out
    }

    /// Render the template for `url`: one line per combination of field values; no lines
    /// when any referenced field has no value. At most [`MAX_LINES_PER_PAGE`] lines.
    #[must_use]
    pub fn render(&self, url: &Url, metadata: &Value) -> Vec<String> {
        let mut lines = vec![String::new()];
        for part in &self.parts {
            match part {
                Part::Literal(text) => {
                    for line in &mut lines {
                        line.push_str(text);
                    }
                }
                Part::Field(field) => {
                    let values = fields::extract(field, url, metadata);
                    if values.is_empty() {
                        return Vec::new();
                    }
                    let mut next = Vec::with_capacity(lines.len().saturating_mul(values.len()));
                    'outer: for prefix in &lines {
                        for value in &values {
                            if next.len() >= MAX_LINES_PER_PAGE {
                                break 'outer;
                            }
                            let mut line = String::with_capacity(prefix.len().saturating_add(value.len()));
                            line.push_str(prefix);
                            line.push_str(value);
                            next.push(line);
                        }
                    }
                    lines = next;
                }
            }
        }
        lines
    }

    /// [`Template::render`] over a stored page.
    #[must_use]
    pub fn render_page(&self, page: &PageRecord) -> Vec<String> {
        self.render(&page.url.url, &page.metadata)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn render(t: &str, url: &str, meta: Value) -> Vec<String> {
        Template::parse(t)
            .unwrap()
            .render(&Url::parse(url).unwrap(), &meta)
    }

    #[test]
    fn literal_and_single_valued_fields_render_one_line() {
        assert_eq!(
            render(
                "{{fqdn}} -> {{path}}",
                "https://a.example.com/x/y?q=1",
                Value::Null
            ),
            ["a.example.com -> /x/y"]
        );
        assert_eq!(render("plain", "https://a.example.com/", Value::Null), ["plain"]);
    }

    #[test]
    fn multi_valued_fields_cross_product_in_order() {
        assert_eq!(
            render("{{key}}={{value}}", "https://e.com/?a=1&b=2", Value::Null),
            ["a=1", "a=2", "b=1", "b=2"]
        );
        let meta = json!({"custom_fields": {"email": ["x@e.com", "y@e.com"]}});
        assert_eq!(
            render("{{email}} - {{url}}", "https://e.com/p", meta),
            ["x@e.com - https://e.com/p", "y@e.com - https://e.com/p"]
        );
    }

    #[test]
    fn missing_field_value_yields_no_line() {
        assert!(render("{{qurl}}", "https://e.com/p", Value::Null).is_empty());
        assert!(render("{{email}}|{{url}}", "https://e.com/p", json!({})).is_empty());
    }

    #[test]
    fn parse_errors() {
        assert_eq!(Template::parse(""), Err(TemplateError::Empty));
        assert_eq!(
            Template::parse("a {{url"),
            Err(TemplateError::Unterminated { offset: 2 })
        );
        assert!(matches!(
            Template::parse("{{no spaces}}"),
            Err(TemplateError::UnknownField(_))
        ));
        let t = Template::parse("{{url}} {{url}} {{kv}}").unwrap();
        assert_eq!(t.fields(), [&Field::Url, &Field::Kv]);
        assert_eq!(t.source(), "{{url}} {{url}} {{kv}}");
    }
}
