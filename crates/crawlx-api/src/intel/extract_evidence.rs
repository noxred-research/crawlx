//! Schema extraction with exact field evidence: the deterministic half.
//!
//! A model proposes *claims*: a JSON pointer, a scalar value, a verbatim quote and the id of the
//! chunk the quote came from. [`verify`] re-derives everything it can: the chunk must exist, the
//! quote must occur in it, the byte span is computed here, and the value must literally occur in
//! the quote. A claim whose quote is not found is `rejected`; a claim with a real quote whose
//! value is only implied is `inferred`; claims that disagree are `conflicting`; required fields
//! nothing supports are `unknown`. Only `observed` fields (and `inferred` ones on request) enter
//! the assembled document, so a plausible hallucination never becomes a fact.

use crate::errors::Detail;
use crate::intel::evidence::{
    ground, locate, pointer_tokens, set_pointer, Chunk, Grounding, Source, MAX_QUOTE_CHARS,
    MAX_SOURCES_PER_REQUEST,
};
use jsonschema::error::ValidationErrorKind;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Prompt label of the extraction call.
pub const PROMPT_VERSION: &str = "evidence-extraction.prompt.v1";
/// Schema label of the claims reply.
pub const SCHEMA_VERSION: &str = "evidence-claims.v1";
/// Most chunks sent in one call.
pub const MAX_CHUNKS: usize = 24;
/// Most fields a result carries.
pub const MAX_FIELDS: usize = 256;
/// Largest schema an extraction accepts (it is part of the model task text).
pub const MAX_TASK_SCHEMA_BYTES: usize = 6000;

/// Versioned schemas for the security inventories researchers extract most often.
pub const PRESETS: [&str; 5] = [
    "endpoint_inventory",
    "forms",
    "auth_mechanisms",
    "api_parameters",
    "response_metadata",
];

/// The schema and version label of a preset.
#[must_use]
pub fn preset(name: &str) -> Option<(&'static str, Value)> {
    let string = json!({"type": "string"});
    let item = |required: &[&str], props: Value| json!({"type": "object", "required": required, "properties": props});
    Some(match name {
        "endpoint_inventory" => (
            "endpoint_inventory.v1",
            json!({"type": "object", "properties": {"endpoints": {"type": "array", "items": item(
                &["method", "path"],
                json!({"method": string, "path": string, "description": string}),
            )}}}),
        ),
        "forms" => (
            "forms.v1",
            json!({"type": "object", "properties": {"forms": {"type": "array", "items": item(
                &["action"],
                json!({"action": string, "method": string, "fields": {"type": "array", "items": item(
                    &["name"],
                    json!({"name": string, "type": string, "required": {"type": "boolean"}}),
                )}}),
            )}}}),
        ),
        "auth_mechanisms" => (
            "auth_mechanisms.v1",
            json!({"type": "object", "properties": {"mechanisms": {"type": "array", "items": item(
                &["kind"],
                json!({"kind": string, "location": string, "description": string}),
            )}}}),
        ),
        "api_parameters" => (
            "api_parameters.v1",
            json!({"type": "object", "properties": {"parameters": {"type": "array", "items": item(
                &["name"],
                json!({"name": string, "location": string, "type": string, "required": {"type": "boolean"}}),
            )}}}),
        ),
        "response_metadata" => (
            "response_metadata.v1",
            json!({"type": "object", "properties": {
                "status": {"type": "integer"}, "contentType": string, "server": string, "title": string,
            }}),
        ),
        _ => return None,
    })
}

/// A validated extraction request.
#[derive(Clone, Debug)]
pub struct Request {
    /// Artifact ids of the retained renditions.
    pub artifacts: Vec<String>,
    /// Canonical URLs of retained pages.
    pub urls: Vec<String>,
    /// The result schema.
    pub schema: Value,
    /// Version label of the schema (`custom` for a caller schema, `<preset>.vN` otherwise).
    pub schema_version: String,
    /// Optional extra task text.
    pub task: Option<String>,
    /// Digests the caller expects, by artifact id.
    pub expected: BTreeMap<String, String>,
    /// Whether inferred fields enter `data`.
    pub include_inferred: bool,
}

/// Parse and validate a request body.
///
/// # Errors
/// Every violation, as `details[]` entries.
pub fn parse_request(body: &Value) -> Result<Request, Vec<Detail>> {
    let mut details = Vec::new();
    let Some(map) = body.as_object() else {
        return Err(vec![Detail::new(
            "/",
            "invalid",
            "the body must be a JSON object",
        )]);
    };
    for key in map.keys() {
        if ![
            "artifacts",
            "urls",
            "schema",
            "preset",
            "task",
            "expectedDigests",
            "includeInferred",
        ]
        .contains(&key.as_str())
        {
            details.push(Detail::new(
                format!("/{key}"),
                "unknown_field",
                format!("unknown field `{key}`"),
            ));
        }
    }
    let strings = |key: &str, details: &mut Vec<Detail>| -> Vec<String> {
        match map.get(key) {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                let list: Vec<String> = items
                    .iter()
                    .filter_map(|v| {
                        v.as_str()
                            .filter(|s| !s.is_empty() && s.len() <= 2048)
                            .map(str::to_owned)
                    })
                    .collect();
                if list.len() != items.len() {
                    details.push(Detail::new(
                        format!("/{key}"),
                        "invalid",
                        "expected non-empty strings",
                    ));
                }
                list
            }
            Some(_) => {
                details.push(Detail::new(
                    format!("/{key}"),
                    "invalid",
                    "expected an array of strings",
                ));
                Vec::new()
            }
        }
    };
    let artifacts = strings("artifacts", &mut details);
    let urls = strings("urls", &mut details);
    if artifacts.len() + urls.len() == 0 || artifacts.len() + urls.len() > MAX_SOURCES_PER_REQUEST {
        details.push(Detail::new(
            "/artifacts",
            "invalid",
            format!("give between 1 and {MAX_SOURCES_PER_REQUEST} artifacts and urls in total"),
        ));
    }
    let mut schema = map.get("schema").cloned().unwrap_or(Value::Null);
    let mut schema_version = "custom".to_owned();
    match (map.get("preset").and_then(Value::as_str), schema.is_null()) {
        (Some(name), true) => match preset(name) {
            Some((version, preset_schema)) => {
                schema = preset_schema;
                schema_version = version.to_owned();
            }
            None => details.push(Detail::new(
                "/preset",
                "invalid",
                format!("preset must be one of {}", PRESETS.join(", ")),
            )),
        },
        (Some(_), false) => details.push(Detail::new(
            "/preset",
            "conflict",
            "give a schema or a preset, not both",
        )),
        (None, _) if map.contains_key("preset") => {
            details.push(Detail::new("/preset", "invalid", "preset must be a string"));
        }
        (None, _) => {}
    }
    if schema.is_null() {
        if !map.contains_key("preset") {
            details.push(Detail::new(
                "/schema",
                "required",
                "a JSON Schema or a preset is required",
            ));
        }
    } else if let Err(e) = crawlx_model::policy::validate_schema_bounds(&schema) {
        details.push(Detail::new("/schema", "invalid_schema", e.to_string()));
    } else if jsonschema::validator_for(&schema).is_err() {
        details.push(Detail::new(
            "/schema",
            "invalid_schema",
            "the schema is not a valid JSON Schema",
        ));
    } else if schema.to_string().len() > MAX_TASK_SCHEMA_BYTES {
        details.push(Detail::new(
            "/schema",
            "invalid_schema",
            format!("the schema must not exceed {MAX_TASK_SCHEMA_BYTES} bytes for an extraction"),
        ));
    }
    let task = match map.get("task") {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) if !t.trim().is_empty() && t.chars().count() <= 2000 => Some(t.clone()),
        Some(_) => {
            details.push(Detail::new(
                "/task",
                "invalid",
                "task must be a non-empty string of at most 2000 characters",
            ));
            None
        }
    };
    let mut expected = BTreeMap::new();
    match map.get("expectedDigests") {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => {
            for (k, v) in m {
                match v.as_str() {
                    Some(d) => {
                        expected.insert(k.clone(), d.to_owned());
                    }
                    None => details.push(Detail::new(
                        "/expectedDigests",
                        "invalid",
                        "digests must be strings",
                    )),
                }
            }
        }
        Some(_) => details.push(Detail::new("/expectedDigests", "invalid", "expected an object")),
    }
    let include_inferred = map
        .get("includeInferred")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if details.is_empty() {
        Ok(Request {
            artifacts,
            urls,
            schema,
            schema_version,
            task,
            expected,
            include_inferred,
        })
    } else {
        Err(details)
    }
}

/// The JSON Schema of a claims reply.
#[must_use]
pub fn claims_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["claims"],
        "properties": {"claims": {
            "type": "array",
            "maxItems": 512,
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["path", "value", "quote", "source"],
                "properties": {
                    "path": {"type": "string", "maxLength": 256},
                    "value": {"type": ["string", "number", "boolean"]},
                    "quote": {"type": "string", "maxLength": MAX_QUOTE_CHARS * 4},
                    "source": {"type": "string", "maxLength": 128},
                },
            },
        }},
    })
}

/// The task text of the extraction call.
#[must_use]
pub fn task_text(request: &Request) -> String {
    let mut text = format!(
        "Extract the fields of this JSON Schema from the sources.\nSchema: {}\n\
         Return a claim per field value: `path` is a JSON pointer into the result document (for example /name or /items/0/url), \
         `value` the scalar, `quote` a verbatim excerpt of one source that contains the value, `source` the id of that source. \
         Never invent a value; omit fields the sources do not state.",
        request.schema
    );
    if let Some(task) = &request.task {
        text.push_str("\nAdditional task: ");
        text.push_str(task);
    }
    text
}

/// Verification state of one field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Quote found, value literally in the quote.
    Observed,
    /// Quote found, value only implied by it.
    Inferred,
    /// Required by the schema, supported by nothing.
    Unknown,
    /// Verified claims disagree.
    Conflicting,
    /// The claim failed verification.
    Rejected,
}

impl Status {
    /// Wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Inferred => "inferred",
            Self::Unknown => "unknown",
            Self::Conflicting => "conflicting",
            Self::Rejected => "rejected",
        }
    }
}

/// Where a verified value was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Artifact id of the rendition.
    pub source: String,
    /// Chunk record id the model cited.
    pub chunk: String,
    /// Byte offset of the quote within the projected source text.
    pub start: usize,
    /// End byte offset (exclusive).
    pub end: usize,
    /// The quote as found in the text.
    pub quote: String,
    /// Digest of the retained bytes.
    pub source_digest: String,
    /// Whether projection changed that source (spans refer to the projected text).
    pub redacted: bool,
}

/// One field of the result.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldResult {
    /// JSON pointer.
    pub path: String,
    /// Verification state.
    pub status: Status,
    /// The value, for observed and inferred fields.
    pub value: Option<Value>,
    /// Evidence for verified claims.
    pub evidence: Vec<Evidence>,
    /// Why a field is rejected, unknown or conflicting.
    pub reason: Option<&'static str>,
    /// Competing values of a conflict.
    pub candidates: Vec<Value>,
}

impl FieldResult {
    /// As JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let evidence: Vec<Value> = self
            .evidence
            .iter()
            .map(|e| {
                json!({
                    "source": e.source, "chunk": e.chunk, "start": e.start, "end": e.end,
                    "quote": e.quote, "sourceDigest": e.source_digest, "projected": e.redacted,
                })
            })
            .collect();
        json!({
            "path": self.path,
            "status": self.status.as_str(),
            "value": self.value,
            "evidence": evidence,
            "reason": self.reason,
            "candidates": self.candidates,
        })
    }
}

fn rejected(path: &str, reason: &'static str) -> FieldResult {
    FieldResult {
        path: path.to_owned(),
        status: Status::Rejected,
        value: None,
        evidence: Vec::new(),
        reason: Some(reason),
        candidates: Vec::new(),
    }
}

/// Verify the claims of a model reply against the chunks that were sent.
#[must_use]
pub fn verify(sources: &[Source], chunks: &[Chunk], reply: &Value) -> Vec<FieldResult> {
    let empty = Vec::new();
    let claims = reply.get("claims").and_then(Value::as_array).unwrap_or(&empty);
    let mut verified: BTreeMap<String, Vec<(Value, Status, Evidence)>> = BTreeMap::new();
    let mut out = Vec::new();
    for claim in claims.iter().take(MAX_FIELDS * 2) {
        let path = claim.get("path").and_then(Value::as_str).unwrap_or_default();
        if pointer_tokens(path).is_none() {
            out.push(rejected(path, "invalid_path"));
            continue;
        }
        let Some(chunk) = claim
            .get("source")
            .and_then(Value::as_str)
            .and_then(|id| chunks.iter().find(|c| c.record_id == id))
        else {
            out.push(rejected(path, "unknown_source"));
            continue;
        };
        let Some(value) = claim.get("value").cloned().filter(|v| !v.is_null()) else {
            out.push(rejected(path, "missing_value"));
            continue;
        };
        let quote = claim.get("quote").and_then(Value::as_str).unwrap_or_default();
        if quote.trim().is_empty() || quote.chars().count() > MAX_QUOTE_CHARS {
            out.push(rejected(path, "missing_quote"));
            continue;
        }
        let Some(source) = sources.get(chunk.source) else {
            out.push(rejected(path, "unknown_source"));
            continue;
        };
        let Some(window) = source.text.get(chunk.range.clone()) else {
            out.push(rejected(path, "unknown_source"));
            continue;
        };
        let Some(span) = locate(window, quote) else {
            out.push(rejected(path, "ungrounded_quote"));
            continue;
        };
        let status = match ground(&value, quote) {
            Grounding::Literal => Status::Observed,
            Grounding::Derived => Status::Inferred,
            Grounding::NotScalar => {
                out.push(rejected(path, "non_scalar"));
                continue;
            }
        };
        let start = chunk.range.start + span.start;
        let end = chunk.range.start + span.end;
        let found = source.text.get(start..end).unwrap_or_default().to_owned();
        verified.entry(path.to_owned()).or_default().push((
            value,
            status,
            Evidence {
                source: source.id.clone(),
                chunk: chunk.record_id.clone(),
                start,
                end,
                quote: found,
                source_digest: source.digest.clone(),
                redacted: source.redacted,
            },
        ));
    }
    for (path, entries) in verified {
        let mut values: Vec<Value> = Vec::new();
        for (value, _, _) in &entries {
            if !values.contains(value) {
                values.push(value.clone());
            }
        }
        let evidence: Vec<Evidence> = entries.iter().map(|(_, _, e)| e.clone()).collect();
        if values.len() > 1 {
            out.push(FieldResult {
                path,
                status: Status::Conflicting,
                value: None,
                evidence,
                reason: Some("contradictory_claims"),
                candidates: values,
            });
            continue;
        }
        let status = if entries.iter().any(|(_, s, _)| *s == Status::Observed) {
            Status::Observed
        } else {
            Status::Inferred
        };
        out.push(FieldResult {
            path,
            status,
            value: values.into_iter().next(),
            evidence,
            reason: (status == Status::Inferred).then_some("value_not_literal_in_quote"),
            candidates: Vec::new(),
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.status.as_str().cmp(b.status.as_str())));
    out.truncate(MAX_FIELDS);
    out
}

/// Paths the schema requires: top-level required properties and those of required nested
/// objects, to a depth of three.
#[must_use]
pub fn required_paths(schema: &Value) -> Vec<String> {
    fn walk(schema: &Value, prefix: &str, depth: usize, out: &mut Vec<String>) {
        if depth > 3 {
            return;
        }
        let Some(required) = schema.get("required").and_then(Value::as_array) else {
            return;
        };
        for name in required.iter().filter_map(Value::as_str) {
            let path = format!("{prefix}/{name}");
            let child = schema.get("properties").and_then(|p| p.get(name));
            let nested = child.is_some_and(|c| c.get("required").is_some());
            if nested {
                if let Some(c) = child {
                    walk(c, &path, depth + 1, out);
                }
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(schema, "", 0, &mut out);
    out
}

/// `unknown` entries for required paths no verified field covers.
#[must_use]
pub fn unknowns(schema: &Value, fields: &[FieldResult]) -> Vec<FieldResult> {
    required_paths(schema)
        .into_iter()
        .filter(|path| {
            !fields.iter().any(|f| {
                matches!(
                    f.status,
                    Status::Observed | Status::Inferred | Status::Conflicting
                ) && (f.path == *path || f.path.starts_with(&format!("{path}/")))
            })
        })
        .map(|path| FieldResult {
            path,
            status: Status::Unknown,
            value: None,
            evidence: Vec::new(),
            reason: Some("not_stated_in_sources"),
            candidates: Vec::new(),
        })
        .collect()
}

/// The document of the fields allowed into `data`.
#[must_use]
pub fn assemble(fields: &[FieldResult], include_inferred: bool) -> (Value, Vec<String>) {
    let mut doc = Value::Null;
    let mut skipped = Vec::new();
    for field in fields {
        let take = match field.status {
            Status::Observed => true,
            Status::Inferred => include_inferred,
            _ => false,
        };
        if !take {
            continue;
        }
        let (Some(value), Some(tokens)) = (field.value.clone(), pointer_tokens(&field.path)) else {
            continue;
        };
        if !set_pointer(&mut doc, &tokens, value) {
            skipped.push(field.path.clone());
        }
    }
    (if doc.is_null() { json!({}) } else { doc }, skipped)
}

/// Schema violations of `doc` other than missing required properties (those are `unknown`
/// fields, not mismatches).
#[must_use]
pub fn mismatches(schema: &Value, doc: &Value) -> Vec<String> {
    let Ok(validator) = jsonschema::validator_for(schema) else {
        return vec!["schema".to_owned()];
    };
    validator
        .iter_errors(doc)
        .filter(|e| !matches!(e.kind(), ValidationErrorKind::Required { .. }))
        .take(5)
        .map(|e| {
            let path = e.instance_path().to_string();
            format!("{}: {e}", if path.is_empty() { "/" } else { path.as_str() })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::intel::evidence::build_chunks;

    fn source(id: &str, text: &str) -> Source {
        Source {
            id: id.to_owned(),
            url: format!("https://x.test/{id}"),
            kind: "markdown",
            text: text.to_owned(),
            digest: format!("digest-{id}"),
            redacted: false,
            status: 200,
        }
    }

    fn fixture() -> (Vec<Source>, Vec<Chunk>) {
        let sources = vec![source(
            "a1",
            "Vendor: Acme Corp\nPlan: Pro\nPrice: EUR 1,299.00 per month\nSupport: ok",
        )];
        let (chunks, _) = build_chunks(&sources, 10);
        (sources, chunks)
    }

    fn claim(path: &str, value: Value, quote: &str) -> Value {
        json!({"path": path, "value": value, "quote": quote, "source": "a1.0"})
    }

    #[test]
    fn observed_fields_carry_exact_spans() {
        let (sources, chunks) = fixture();
        let fields = verify(
            &sources,
            &chunks,
            &json!({"claims": [claim("/vendor", json!("Acme Corp"), "Vendor: Acme Corp")]}),
        );
        assert_eq!(fields.len(), 1);
        let f = &fields[0];
        assert_eq!(f.status, Status::Observed);
        let e = &f.evidence[0];
        assert_eq!(&sources[0].text[e.start..e.end], "Vendor: Acme Corp");
        assert_eq!(e.source_digest, "digest-a1");
    }

    #[test]
    fn hallucinated_values_and_quotes_never_become_facts() {
        let (sources, chunks) = fixture();
        let reply = json!({"claims": [
            claim("/vendor", json!("Globex"), "Vendor: Globex"),
            claim("/plan", json!("Enterprise"), "Plan: Pro"),
            {"path": "/x", "value": "y", "quote": "Plan: Pro", "source": "other.0"},
            claim("/../etc", json!("y"), "Plan: Pro"),
            claim("/obj", json!({"a": 1}), "Plan: Pro"),
            {"path": "/novalue", "quote": "Plan: Pro", "source": "a1.0"},
        ]});
        let fields = verify(&sources, &chunks, &reply);
        let status = |p: &str| fields.iter().find(|f| f.path == p).map(|f| (f.status, f.reason));
        assert_eq!(
            status("/vendor"),
            Some((Status::Rejected, Some("ungrounded_quote")))
        );
        assert_eq!(
            status("/plan"),
            Some((Status::Inferred, Some("value_not_literal_in_quote")))
        );
        assert_eq!(status("/x"), Some((Status::Rejected, Some("unknown_source"))));
        assert_eq!(status("/obj"), Some((Status::Rejected, Some("non_scalar"))));
        assert_eq!(
            status("/novalue"),
            Some((Status::Rejected, Some("missing_value")))
        );
        let (doc, _) = assemble(&fields, false);
        assert_eq!(doc, json!({}), "nothing unverified enters the document");
        let (with_inferred, _) = assemble(&fields, true);
        assert_eq!(with_inferred, json!({"plan": "Enterprise"}));
    }

    #[test]
    fn conflicting_claims_are_reported_not_resolved() {
        let (sources, chunks) = fixture();
        let reply = json!({"claims": [
            claim("/price", json!(1299), "EUR 1,299.00"),
            claim("/price", json!(1300), "Price: EUR 1,299.00"),
            claim("/price", json!(1299), "Price: EUR 1,299.00 per month"),
        ]});
        let fields = verify(&sources, &chunks, &reply);
        let price = fields.iter().find(|f| f.path == "/price").unwrap();
        assert_eq!(price.status, Status::Conflicting);
        assert_eq!(price.candidates.len(), 2);
        assert!(price.value.is_none());
    }

    #[test]
    fn short_scalars_are_not_observed_by_substring() {
        let (sources, chunks) = fixture();
        let fields = verify(
            &sources,
            &chunks,
            &json!({"claims": [claim("/ok", json!("ok"), "Support: ok"), claim("/p", json!("o"), "Plan: Pro")]}),
        );
        let by = |p: &str| fields.iter().find(|f| f.path == p).unwrap().status;
        assert_eq!(by("/ok"), Status::Observed);
        assert_eq!(
            by("/p"),
            Status::Inferred,
            "a single letter matches only as a whole token"
        );
    }

    #[test]
    fn required_fields_without_support_are_unknown() {
        let schema = json!({"type": "object", "required": ["vendor", "owner"], "properties": {"vendor": {"type": "string"}, "owner": {"type": "string"}}});
        let (sources, chunks) = fixture();
        let fields = verify(
            &sources,
            &chunks,
            &json!({"claims": [claim("/vendor", json!("Acme Corp"), "Vendor: Acme Corp")]}),
        );
        let unknown = unknowns(&schema, &fields);
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].path, "/owner");
        assert_eq!(unknown[0].status, Status::Unknown);
        let (doc, _) = assemble(&fields, false);
        assert!(
            mismatches(&schema, &doc).is_empty(),
            "missing required fields are unknown, not mismatches"
        );
        let bad = json!({"type": "object", "properties": {"vendor": {"type": "integer"}}});
        assert!(!mismatches(&bad, &doc).is_empty());
    }

    #[test]
    fn requests_are_validated() {
        assert!(parse_request(&json!({"artifacts": ["a"], "schema": {"type": "object"}})).is_ok());
        assert!(parse_request(&json!({"schema": {"type": "object"}})).is_err());
        assert!(parse_request(&json!({"artifacts": ["a"]})).is_err());
        assert!(
            parse_request(&json!({"artifacts": ["a"], "schema": {"$ref": "https://evil.test/s"}})).is_err()
        );
        assert!(parse_request(&json!({"artifacts": ["a"], "schema": {"type": "banana"}})).is_err());
        assert!(
            parse_request(&json!({"artifacts": ["a"], "schema": {"type": "object"}, "shell": 1})).is_err()
        );
    }

    #[test]
    fn presets_are_valid_bounded_schemas() {
        for name in PRESETS {
            let (version, schema) = preset(name).unwrap();
            assert!(version.starts_with(name) && version.ends_with(".v1"));
            crawlx_model::policy::validate_schema_bounds(&schema).unwrap();
            jsonschema::validator_for(&schema).unwrap();
            let request = parse_request(&json!({"artifacts": ["a"], "preset": name})).unwrap();
            assert_eq!(request.schema_version, version);
        }
        assert!(parse_request(&json!({"artifacts": ["a"], "preset": "nope"})).is_err());
        assert!(
            parse_request(&json!({"artifacts": ["a"], "preset": "forms", "schema": {"type": "object"}}))
                .is_err()
        );
        let (_, forms) = preset("forms").unwrap();
        let doc = json!({"forms": [{"action": "/login", "method": "POST", "fields": [{"name": "user"}]}]});
        assert!(mismatches(&forms, &doc).is_empty());
        let bad = json!({"forms": [{"action": 5}]});
        assert!(!mismatches(&forms, &bad).is_empty());
    }
}
