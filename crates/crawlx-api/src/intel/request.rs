//! A strict reader for the compat API request bodies: typed accessors that collect every violation
//! as a [`Detail`] with a JSON-pointer path, so a request with three wrong fields answers one
//! `422` listing all three, and the unknown top-level keys the product does not use.

use crate::errors::{Detail, HttpError};
use serde_json::{Map, Value};

/// Reader over one JSON object.
#[derive(Debug)]
pub struct Body<'a> {
    obj: &'a Map<String, Value>,
    prefix: String,
    details: Vec<Detail>,
}

impl<'a> Body<'a> {
    /// Read `value` as the request body.
    ///
    /// # Errors
    /// `422 validation` when the body is not a JSON object.
    pub fn new(value: &'a Value) -> Result<Self, HttpError> {
        let obj = value.as_object().ok_or_else(|| {
            HttpError::validation(vec![Detail::new("/", "required", "body must be a JSON object")])
        })?;
        Ok(Self {
            obj,
            prefix: String::new(),
            details: Vec::new(),
        })
    }

    fn path(&self, key: &str) -> String {
        format!("{}/{key}", self.prefix)
    }

    /// Record a violation at `key`.
    pub fn fail(&mut self, key: &str, code: &str, message: impl Into<String>) {
        let path = self.path(key);
        self.details.push(Detail::new(path, code, message));
    }

    /// The raw value of `key` (`null` counts as absent).
    #[must_use]
    pub fn raw(&self, key: &str) -> Option<&'a Value> {
        self.obj.get(key).filter(|v| !v.is_null())
    }

    /// A string of at most `max` characters.
    pub fn string(&mut self, key: &str, max: usize) -> Option<String> {
        let v = self.raw(key)?;
        match v.as_str() {
            Some(s) if s.chars().count() <= max => Some(s.to_owned()),
            Some(_) => {
                self.fail(key, "out_of_range", format!("at most {max} characters"));
                None
            }
            None => {
                self.fail(key, "invalid_type", "expected a string");
                None
            }
        }
    }

    /// A required, non-blank string of at most `max` characters.
    pub fn required_string(&mut self, key: &str, max: usize) -> Option<String> {
        match self.string(key, max) {
            Some(s) if !s.trim().is_empty() => Some(s),
            Some(_) => {
                self.fail(key, "required", format!("{key} must not be empty"));
                None
            }
            None => {
                if self.raw(key).is_none() {
                    self.fail(key, "required", format!("{key} is required"));
                }
                None
            }
        }
    }

    /// A boolean.
    pub fn boolean(&mut self, key: &str) -> Option<bool> {
        let v = self.raw(key)?;
        v.as_bool().or_else(|| {
            self.fail(key, "invalid_type", "expected a boolean");
            None
        })
    }

    /// An unsigned integer in `min..=max`.
    pub fn integer(&mut self, key: &str, min: u64, max: u64) -> Option<u64> {
        let v = self.raw(key)?;
        match v.as_u64() {
            Some(n) if (min..=max).contains(&n) => Some(n),
            Some(_) => {
                self.fail(key, "out_of_range", format!("expected {min} to {max}"));
                None
            }
            None => {
                self.fail(key, "invalid_type", "expected an integer");
                None
            }
        }
    }

    /// An array of strings, at most `max_items` items of at most `max_len` characters.
    pub fn strings(&mut self, key: &str, max_items: usize, max_len: usize) -> Option<Vec<String>> {
        let v = self.raw(key)?;
        let Some(items) = v.as_array() else {
            self.fail(key, "invalid_type", "expected an array of strings");
            return None;
        };
        if items.len() > max_items {
            self.fail(key, "out_of_range", format!("at most {max_items} items"));
            return None;
        }
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            match item.as_str() {
                Some(s) if s.chars().count() <= max_len => out.push(s.to_owned()),
                _ => {
                    self.fail(
                        &format!("{key}/{i}"),
                        "invalid_type",
                        format!("expected a string of at most {max_len} characters"),
                    );
                    return None;
                }
            }
        }
        Some(out)
    }

    /// A JSON object (kept as a value).
    pub fn object(&mut self, key: &str) -> Option<&'a Value> {
        let v = self.raw(key)?;
        if v.is_object() {
            Some(v)
        } else {
            self.fail(key, "invalid_type", "expected an object");
            None
        }
    }

    /// A JSON array (kept as a value).
    pub fn array(&mut self, key: &str) -> Option<&'a [Value]> {
        let v = self.raw(key)?;
        v.as_array().map(Vec::as_slice).or_else(|| {
            self.fail(key, "invalid_type", "expected an array");
            None
        })
    }

    /// Top-level keys of the body that are not in `known` (sorted), for a `warnings` entry.
    #[must_use]
    pub fn unknown_keys(&self, known: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = self
            .obj
            .keys()
            .filter(|k| !known.contains(&k.as_str()))
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Whether a violation has been recorded.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.details.is_empty()
    }

    /// Finish reading.
    ///
    /// # Errors
    /// `422 validation` listing every recorded violation.
    pub fn finish(self) -> Result<(), HttpError> {
        if self.details.is_empty() {
            Ok(())
        } else {
            Err(HttpError::validation(self.details))
        }
    }
}

/// An absolute http(s) URL string.
#[must_use]
pub fn is_http_url(s: &str) -> bool {
    url::Url::parse(s).is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn collects_every_violation_with_pointer_paths() {
        let v = json!({"query": 5, "limit": 500, "flag": "yes", "list": ["a", 2]});
        let mut b = Body::new(&v).unwrap();
        assert!(b.required_string("query", 10).is_none());
        assert!(b.integer("limit", 1, 100).is_none());
        assert!(b.boolean("flag").is_none());
        assert!(b.strings("list", 5, 5).is_none());
        let err = b.finish().unwrap_err();
        let paths: Vec<&str> = err.details.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, ["/query", "/limit", "/flag", "/list/1"]);
    }

    #[test]
    fn missing_required_and_unknown_keys() {
        let v = json!({"query": "  ", "x": 1, "a": null});
        let mut b = Body::new(&v).unwrap();
        assert!(b.required_string("query", 10).is_none());
        assert!(b.required_string("missing", 10).is_none());
        assert_eq!(
            b.unknown_keys(&["query"]),
            ["a", "x"].map(String::from),
            "null members still count as present keys"
        );
        assert_eq!(b.finish().unwrap_err().details.len(), 2);
        assert!(Body::new(&json!([1])).is_err());
    }

    #[test]
    fn valid_values_pass() {
        let v = json!({"q": "hi", "n": 3, "b": true, "s": ["a"], "o": {"k": 1}, "arr": [1]});
        let mut b = Body::new(&v).unwrap();
        assert_eq!(b.required_string("q", 10).as_deref(), Some("hi"));
        assert_eq!(b.integer("n", 1, 5), Some(3));
        assert_eq!(b.boolean("b"), Some(true));
        assert_eq!(b.strings("s", 2, 2).unwrap(), ["a"]);
        assert!(b.object("o").is_some());
        assert_eq!(b.array("arr").unwrap().len(), 1);
        assert!(b.finish().is_ok());
        assert!(is_http_url("https://a.com/x") && !is_http_url("ftp://a") && !is_http_url("nope"));
    }
}
