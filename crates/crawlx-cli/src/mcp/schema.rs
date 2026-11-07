//! Validation of tool arguments against the JSON Schema subset the tools advertise.
//!
//! The same schema value is sent to the client in `tools/list` and used here, so what a
//! tool advertises is what it enforces. Supported keywords: `type`, `enum`, `properties`,
//! `required`, `additionalProperties` (as a schema), `items`, `minimum`, `maximum`,
//! `minLength`, `maxLength`, `minItems`, `maxItems` and `format` (`uri`, `uuid`).
//!
//! Like the upstream Firecrawl MCP server (which validates with zod), the check is
//! tolerant on the way in: `null` values and blank strings of optional properties count as
//! absent, and properties the schema does not list are dropped instead of rejected.

use serde_json::{Map, Value};

/// Most issues reported at once; the model fixes them in one round trip.
const MAX_ISSUES: usize = 8;

/// Check `value` against `schema` and return it with unlisted object properties removed.
///
/// # Errors
/// Returns every violation found (at most [`MAX_ISSUES`]), each prefixed with the JSON path
/// of the offending value.
pub(crate) fn check(schema: &Value, value: Value) -> Result<Value, Vec<String>> {
    let mut issues = Vec::new();
    let checked = walk(schema, value, "arguments", &mut issues);
    if issues.is_empty() {
        Ok(checked)
    } else {
        Err(issues)
    }
}

fn walk(schema: &Value, value: Value, path: &str, issues: &mut Vec<String>) -> Value {
    if issues.len() >= MAX_ISSUES {
        return value;
    }
    let Some(schema) = schema.as_object() else {
        return value;
    };
    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        if !type_matches(expected, &value) {
            issues.push(format!(
                "{path} must be {} (got {})",
                describe_type(expected),
                kind(&value)
            ));
            return value;
        }
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array) {
        if !options.contains(&value) {
            let list: Vec<String> = options.iter().map(Value::to_string).collect();
            issues.push(format!("{path} must be one of {}", list.join(", ")));
            return value;
        }
    }
    match value {
        Value::Object(map) => Value::Object(walk_object(schema, map, path, issues)),
        Value::Array(items) => Value::Array(walk_array(schema, items, path, issues)),
        Value::String(text) => {
            check_string(schema, &text, path, issues);
            Value::String(text)
        }
        Value::Number(number) => {
            if let Some(n) = number.as_f64() {
                check_number(schema, n, path, issues);
            }
            Value::Number(number)
        }
        other => other,
    }
}

fn walk_object(
    schema: &Map<String, Value>,
    map: Map<String, Value>,
    path: &str,
    issues: &mut Vec<String>,
) -> Map<String, Value> {
    let properties = schema.get("properties").and_then(Value::as_object);
    let extra = schema.get("additionalProperties").filter(|v| v.is_object());
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut out = Map::new();
    for (key, value) in map {
        let is_required = required.contains(&key.as_str());
        // `null` always counts as absent (a required one is then reported missing); a blank
        // string only for optional properties
        let blank = match &value {
            Value::Null => true,
            Value::String(text) => !is_required && text.trim().is_empty(),
            _ => false,
        };
        if blank {
            continue;
        }
        let child_path = format!("{path}.{key}");
        let sub_schema = properties.and_then(|props| props.get(&key)).or(extra);
        match (sub_schema, properties) {
            (Some(sub), _) => {
                let checked = walk(sub, value, &child_path, issues);
                out.insert(key, checked);
            }
            (None, Some(_)) => {} // not listed: dropped
            (None, None) => {
                out.insert(key, value);
            }
        }
    }
    for name in required {
        if !out.contains_key(name) {
            issues.push(format!("{path}.{name} is required"));
        }
    }
    out
}

fn walk_array(
    schema: &Map<String, Value>,
    items: Vec<Value>,
    path: &str,
    issues: &mut Vec<String>,
) -> Vec<Value> {
    let length = u64::try_from(items.len()).unwrap_or(u64::MAX);
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
        if length < min {
            issues.push(format!("{path} must have at least {min} item(s)"));
        }
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
        if length > max {
            issues.push(format!("{path} must have at most {max} item(s)"));
        }
    }
    let Some(item_schema) = schema.get("items") else {
        return items;
    };
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| walk(item_schema, item, &format!("{path}[{index}]"), issues))
        .collect()
}

fn check_string(schema: &Map<String, Value>, text: &str, path: &str, issues: &mut Vec<String>) {
    let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
        if length < min {
            issues.push(format!("{path} must be at least {min} character(s) long"));
        }
    }
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
        if length > max {
            issues.push(format!("{path} must be at most {max} character(s) long"));
        }
    }
    match schema.get("format").and_then(Value::as_str) {
        Some("uri") if !is_http_url(text) => {
            issues.push(format!("{path} must be an absolute http(s) URL"));
        }
        Some("uuid") if uuid::Uuid::parse_str(text).is_err() => {
            issues.push(format!("{path} must be a UUID"));
        }
        _ => {}
    }
}

fn check_number(schema: &Map<String, Value>, n: f64, path: &str, issues: &mut Vec<String>) {
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
        if n < min {
            issues.push(format!("{path} must be at least {min}"));
        }
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
        if n > max {
            issues.push(format!("{path} must be at most {max}"));
        }
    }
}

fn is_http_url(text: &str) -> bool {
    url::Url::parse(text).is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        _ => true,
    }
}

fn describe_type(expected: &str) -> &str {
    match expected {
        "string" => "a string",
        "boolean" => "a boolean",
        "object" => "an object",
        "array" => "an array",
        "number" => "a number",
        "integer" => "an integer",
        other => other,
    }
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
