//! Shared JSON inspection that never collapses duplicate object members.

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{map::Entry, Map, Number, Value};
use std::fmt;

pub(super) enum JsonDocument {
    Value(Value),
    DuplicateMembers,
    Other,
}

pub(super) fn inspect_json(bytes: &[u8]) -> JsonDocument {
    let mut duplicate = false;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = UniqueJson {
        duplicate: &mut duplicate,
    }
    .deserialize(&mut deserializer);
    if duplicate {
        return JsonDocument::DuplicateMembers;
    }
    match result {
        Ok(value) if deserializer.end().is_ok() => JsonDocument::Value(value),
        _ => JsonDocument::Other,
    }
}

/// Check raw bytes and every decoded JSON string or object name with one secret predicate.
///
/// Duplicate JSON names are treated as unsafe, even when their last value appears clean:
/// different consumers can recover different values from that ambiguous representation.
/// Non-JSON binary bytes are checked without lossy decoding or rewriting. The predicate
/// should inspect the supplied bytes for the caller's existing scoped literal secrets.
#[must_use]
pub fn contains_secret_bytes(bytes: &[u8], contains: impl Fn(&[u8]) -> bool) -> bool {
    if contains(bytes) {
        return true;
    }
    match inspect_json(bytes) {
        JsonDocument::Value(value) => json_contains(&value, &contains),
        JsonDocument::DuplicateMembers => true,
        JsonDocument::Other => false,
    }
}

fn json_contains(value: &Value, contains: &impl Fn(&[u8]) -> bool) -> bool {
    match value {
        Value::String(text) => contains(text.as_bytes()),
        Value::Array(values) => values.iter().any(|value| json_contains(value, contains)),
        Value::Object(values) => values
            .iter()
            .any(|(name, value)| contains(name.as_bytes()) || json_contains(value, contains)),
        _ => false,
    }
}

struct UniqueJson<'a> {
    duplicate: &'a mut bool,
}

impl<'de> DeserializeSeed<'de> for UniqueJson<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueJson<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object members")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(UniqueJson {
            duplicate: &mut *self.duplicate,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(name) = access.next_key::<String>()? {
            let entry = match values.entry(name) {
                Entry::Vacant(entry) => entry,
                Entry::Occupied(_) => {
                    *self.duplicate = true;
                    return Err(A::Error::custom("duplicate JSON member"));
                }
            };
            entry.insert(access.next_value_seed(UniqueJson {
                duplicate: &mut *self.duplicate,
            })?);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn duplicate_names_are_compared_after_decoding_and_at_every_depth() {
        for bytes in [
            br#"{"data":1,"d\u0061ta":2}"#.as_slice(),
            br#"{"nested":[{"data":1,"data":2}]}"#,
        ] {
            assert!(matches!(inspect_json(bytes), JsonDocument::DuplicateMembers));
            assert!(contains_secret_bytes(bytes, |_| false));
        }
    }

    #[test]
    fn inspection_preserves_json_values_and_non_json_binary_policy() {
        let input = br#"{"array":[null,true,false,-2,3,4.5,"decoded\u0020value"],"nested":{}}"#;
        let JsonDocument::Value(parsed) = inspect_json(input) else {
            panic!("valid unique JSON must be decoded");
        };
        assert_eq!(parsed, serde_json::from_slice::<Value>(input).unwrap());
        assert!(contains_secret_bytes(input, |part| part == b"decoded value"));
        assert!(!contains_secret_bytes(b"\xff\0native", |part| part == b"decoded value"));
        assert!(contains_secret_bytes(b"\xff\0native", |part| part.ends_with(b"native")));
    }
}
