//! The compatibility `-fc` form-config file (a YAML mapping of five keys).
//!
//! ```yaml
//! email: "rand_email()"
//! phone: "rand_phone()"
//! placeholder: "rand_first_name()"
//! password: 'rand_base(16, "")'
//! color: "#e66465"
//! ```
//!
//! The reference implementation decodes the file into five strings and evaluates `rand_*` calls
//! through its DSL engine at load time. Here the strings are kept as written
//! (the supported `rand_*` calls are evaluated per run seed by
//! [`fill_form`](super::fill_form)) and a key left out (or empty) stays `None`,
//! so the seeded default applies instead of an empty value.

use crawlx_core::config::FormFill;
use serde_yaml_ng::Value;

/// Errors of [`parse_form_config`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormConfigError {
    /// The text is not valid YAML.
    #[error("form config is not valid yaml")]
    Yaml(#[from] serde_yaml_ng::Error),
    /// The document is not a mapping of keys to scalar values.
    #[error("form config must be a mapping of email, color, password, phone, placeholder to scalar values")]
    NotAMapping,
    /// A key other than `email`, `color`, `password`, `phone`, `placeholder`.
    #[error("unknown form config key `{0}` (expected email, color, password, phone or placeholder)")]
    UnknownKey(String),
    /// A value that is not a string, number or boolean.
    #[error("form config key `{0}` must be a scalar value")]
    NotScalar(String),
}

/// Parse a compatibility `-fc` YAML document.
///
/// Scalars (strings, numbers, booleans) are accepted as the value of
/// `email`, `color`, `password`, `phone` and `placeholder`; an empty document
/// or an empty string leaves the key unset. The result has `enabled: false`:
/// `-fc` supplies values, `-aff` turns filling on.
///
/// # Errors
///
/// [`FormConfigError`] when the text is not YAML, is not a mapping, names a
/// key the reference does not know, or holds a non-scalar value.
pub fn parse_form_config(text: &str) -> Result<FormFill, FormConfigError> {
    let doc: Value = serde_yaml_ng::from_str(text)?;
    let map = match doc {
        Value::Null => return Ok(FormFill::default()),
        Value::Mapping(map) => map,
        _ => return Err(FormConfigError::NotAMapping),
    };
    let mut fill = FormFill::default();
    for (key, value) in map {
        let Value::String(key) = key else {
            return Err(FormConfigError::NotAMapping);
        };
        let text = match value {
            Value::Null => None,
            Value::String(s) => Some(s),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => return Err(FormConfigError::NotScalar(key)),
        }
        .filter(|s| !s.is_empty());
        match key.as_str() {
            "email" => fill.email = text,
            "color" => fill.color = text,
            "password" => fill.password = text,
            "phone" => fill.phone = text,
            "placeholder" => fill.placeholder = text,
            _ => return Err(FormConfigError::UnknownKey(key)),
        }
    }
    Ok(fill)
}
