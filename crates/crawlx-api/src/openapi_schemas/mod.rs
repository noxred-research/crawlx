//! Request and response schemas of the facade operations, generated from Rust types.
//!
//! The facade parses most requests by hand from a [`serde_json::Value`] (a JSON body, a
//! multipart `options` part or the query string), so no serde type states the accepted keys.
//! The structs of the sub-modules are **schema-only mirrors** of those parsers: they derive
//! [`schemars::JsonSchema`], carry the documentation of every key as doc comments and are never
//! constructed. Request types are generated with serde's *deserialize* contract (`Option`
//! members are optional and accept `null`, which every parser reads as absent); response types
//! with the *serialize* contract (a plain `Option` member is always present and nullable,
//! `skip_serializing_if` makes it optional). Drift between a mirror and its parser is caught by
//! `tests/openapi_schemas.rs`, which sends every key of every request schema to the real
//! handler and validates real responses against the response schemas.
//!
//! [`spec`] maps an operation id to its [`Spec`]; [`Spec::apply`] writes the `requestBody`,
//! `parameters` and `responses` of one operation into the document and registers the schemas it
//! references in [`Schemas`], whose [`Schemas::finish`] yields `components.schemas`.

#![allow(
    dead_code,
    reason = "the schema mirrors are only reflected on by `JsonSchema`; their members are never read"
)]

mod agent;
mod common;
mod crawl;
mod datasets;
mod extract;
mod map;
mod monitor;
mod native;
mod outputs;
mod parse;
mod reports;
mod scrape;
mod search;
mod selectors;
mod team;
mod watch;

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub(crate) fn apply_native(schemas: &mut Schemas, operation: &mut Value, id: &str) {
    native::apply(schemas, operation, id);
}

/// Adds the schema of one type to a generator and returns the schema or a `$ref` to it.
type SchemaFn = fn(&mut SchemaGenerator) -> Schema;

/// The schema of `T`.
fn schema_of<T: JsonSchema>(g: &mut SchemaGenerator) -> Schema {
    g.subschema_for::<T>()
}

/// Generator settings shared by requests and responses: JSON Schema 2020-12 (what OpenAPI 3.1
/// embeds), references into `components.schemas`, no `$schema` on sub-schemas.
fn settings() -> SchemaSettings {
    SchemaSettings::draft2020_12().with(|s| {
        s.definitions_path = "/components/schemas".into();
        s.meta_schema = None;
    })
}

/// The two generators of a document: request types (deserialize contract) and response types
/// (serialize contract).
pub(crate) struct Schemas {
    req: SchemaGenerator,
    res: SchemaGenerator,
}

impl Schemas {
    /// Empty generators.
    pub(crate) fn new() -> Self {
        Self {
            req: settings().for_deserialize().into_generator(),
            res: settings().for_serialize().into_generator(),
        }
    }

    /// Everything generated so far as `components.schemas`, sorted by name. Request and response
    /// types never share a name (a clash would be renamed by the generator and shows up in the
    /// drift tests as a duplicate component).
    pub(crate) fn finish(mut self) -> BTreeMap<String, Value> {
        let mut out: BTreeMap<String, Value> = BTreeMap::new();
        for (name, schema) in self.req.take_definitions(true) {
            out.insert(name, schema);
        }
        for (name, schema) in self.res.take_definitions(true) {
            out.entry(name).or_insert(schema);
        }
        out
    }
}

/// The error schema shared by every facade operation (`{success:false, error, code, details[]}`).
pub(crate) const FACADE_ERROR: &str = "FacadeError";

/// What a request body is made of.
#[derive(Clone, Copy)]
enum Body {
    /// `application/json` described by the schema.
    Json(SchemaFn),
    /// `multipart/form-data` described by the schema (a `file` part and an `options` part).
    Multipart(SchemaFn),
}

/// One documented response of an operation.
#[derive(Clone, Copy)]
struct Reply {
    status: &'static str,
    description: &'static str,
    schema: SchemaFn,
}

/// A documented path parameter (the default is a UUID called by its name).
#[derive(Clone, Copy)]
struct PathDoc {
    name: &'static str,
    description: &'static str,
    format: Option<&'static str>,
}

/// Everything the document says about one operation beyond its id, summary and scope.
pub(crate) struct Spec {
    body: Option<Body>,
    body_description: &'static str,
    query: Option<fn() -> Vec<Value>>,
    paths: Vec<PathDoc>,
    headers: Vec<(&'static str, &'static str)>,
    replies: Vec<Reply>,
    errors: Vec<u16>,
}

/// Status codes every authenticated facade operation can answer: `401` (missing or invalid key),
/// `403` (`scope_missing`), `429` (`rate_limited`) and `500`.
const AUTHENTICATED: [u16; 4] = [401, 403, 429, 500];

impl Spec {
    /// A spec whose error statuses are the authenticated baseline plus `extra`.
    fn new(extra: &[u16]) -> Self {
        let mut errors: Vec<u16> = AUTHENTICATED.iter().chain(extra).copied().collect();
        errors.sort_unstable();
        errors.dedup();
        Self {
            body: None,
            body_description: "",
            query: None,
            paths: Vec::new(),
            headers: Vec::new(),
            replies: Vec::new(),
            errors,
        }
    }

    /// A spec of an unauthenticated operation: only `extra` error statuses.
    fn open(extra: &[u16]) -> Self {
        let mut s = Self::new(&[]);
        s.errors = extra.to_vec();
        s
    }

    /// Add error statuses.
    fn add_errors(mut self, extra: &[u16]) -> Self {
        self.errors.extend_from_slice(extra);
        self.errors.sort_unstable();
        self.errors.dedup();
        self
    }

    /// The request body is JSON described by `T` (so `400` for invalid JSON and `413` for a body
    /// above the limit are possible).
    fn json<T: JsonSchema>(mut self, description: &'static str) -> Self {
        self.body = Some(Body::Json(schema_of::<T>));
        self.body_description = description;
        self.add_errors(&[400, 413])
    }

    /// The request body is `multipart/form-data` described by `T` (`400` for a malformed upload,
    /// `413` above the upload limit).
    fn multipart<T: JsonSchema>(mut self, description: &'static str) -> Self {
        self.body = Some(Body::Multipart(schema_of::<T>));
        self.body_description = description;
        self.add_errors(&[400, 413])
    }

    /// The query string is the object `T`.
    fn query<T: JsonSchema>(mut self) -> Self {
        self.query = Some(query_parameters::<T>);
        self
    }

    /// Document path parameter `name`.
    fn path(mut self, name: &'static str, description: &'static str, format: Option<&'static str>) -> Self {
        self.paths.push(PathDoc {
            name,
            description,
            format,
        });
        self
    }

    /// Document request header `name`.
    fn header(mut self, name: &'static str, description: &'static str) -> Self {
        self.headers.push((name, description));
        self
    }

    /// A JSON response of `status` described by `T`.
    fn reply<T: JsonSchema>(mut self, status: &'static str, description: &'static str) -> Self {
        self.replies.push(Reply {
            status,
            description,
            schema: schema_of::<T>,
        });
        self
    }

    /// Write `requestBody`, `parameters` and `responses` of this spec into `op` (an operation
    /// object that already holds the id, summary and security).
    pub(crate) fn apply(&self, schemas: &mut Schemas, op: &mut Value) {
        let Some(obj) = op.as_object_mut() else {
            return;
        };
        let mut params: Vec<Value> = obj
            .get("parameters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for p in &self.paths {
            let mut schema = json!({ "type": "string" });
            if let (Some(f), Some(o)) = (p.format, schema.as_object_mut()) {
                o.insert("format".to_owned(), json!(f));
            }
            let doc = json!({
                "name": p.name, "in": "path", "required": true,
                "description": p.description, "schema": schema,
            });
            match params
                .iter_mut()
                .find(|x| x["in"] == "path" && x["name"] == p.name)
            {
                Some(slot) => *slot = doc,
                None => params.push(doc),
            }
        }
        if let Some(query) = self.query {
            params.extend(query());
        }
        for (name, description) in &self.headers {
            params.push(json!({
                "name": name, "in": "header", "required": false,
                "description": description, "schema": { "type": "string" },
            }));
        }
        obj.insert("parameters".to_owned(), Value::Array(params));

        if let Some(body) = self.body {
            let (media, f) = match body {
                Body::Json(f) => ("application/json", f),
                Body::Multipart(f) => ("multipart/form-data", f),
            };
            let schema = f(&mut schemas.req);
            let mut media_object = json!({ "schema": schema });
            if media == "multipart/form-data" {
                media_object["encoding"] = json!({ "options": { "contentType": "application/json" } });
            }
            let mut content = Map::new();
            content.insert(media.to_owned(), media_object);
            obj.insert(
                "requestBody".to_owned(),
                json!({ "required": true, "description": self.body_description, "content": content }),
            );
        }

        let mut responses = Map::new();
        for r in &self.replies {
            let schema = (r.schema)(&mut schemas.res);
            responses.insert(
                r.status.to_owned(),
                json!({
                    "description": r.description,
                    "content": { "application/json": { "schema": schema } },
                }),
            );
        }
        let error = schemas.res.subschema_for::<common::FacadeError>();
        for code in &self.errors {
            responses.insert(
                code.to_string(),
                json!({
                    "description": error_text(*code),
                    "content": { "application/json": { "schema": error } },
                }),
            );
        }
        obj.insert("responses".to_owned(), Value::Object(responses));
    }
}

/// What an error status means on the facade.
fn error_text(status: u16) -> &'static str {
    match status {
        400 => "BAD_REQUEST or malformed_request: invalid JSON, option, path or query value (`details[]` lists every violation)",
        401 => "unauthenticated: the API key is missing, invalid or revoked",
        403 => "scope_missing, UNSUPPORTED_SITE (egress policy), SCRAPE_PROMPT_INJECTION_DETECTED",
        404 => "not_found: unknown id, another tenant's resource or a resource of another kind; no cached scrape for minAge or lockdown",
        408 => "SCRAPE_TIMEOUT: the request outlived its `timeout`",
        409 => "conflict: engine_mismatch, invalid_state, duplicate_request, request_in_flight, agent_finished, agent_cancelled",
        410 => "zdr_expired: the zero-data-retention result was deleted",
        413 => "payload_too_large: the body or upload exceeds its limit",
        415 => "unsupported_content_type: the uploaded file type is not supported",
        422 => "validation_failed, idempotency_key_reuse, url_denied or a document the parser cannot read (`details[]`)",
        429 => "rate_limited or quota_exceeded (concurrency limit reached)",
        500 => "internal, or the failure code of a scraped page (SCRAPE_SITE_ERROR, SCRAPE_ALL_ENGINES_FAILED, ...)",
        502 => "search_unavailable or an LLM failure",
        503 => "llm_not_configured, search_not_configured, scrape_unavailable or storage unavailable",
        504 => "search_timeout or an LLM timeout",
        _ => "error",
    }
}

/// The `parameters` of the query-string object `T`: one entry per property, in name order.
fn query_parameters<T: JsonSchema>() -> Vec<Value> {
    let mut generator = settings().with(|s| s.inline_subschemas = true).into_generator();
    let root = generator.root_schema_for::<T>().to_value();
    let required: Vec<&str> = root["required"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(props) = root["properties"].as_object() else {
        return Vec::new();
    };
    props
        .iter()
        .map(|(name, schema)| {
            let mut schema = schema.clone();
            let description = schema
                .as_object_mut()
                .and_then(|o| o.remove("description"))
                .unwrap_or(Value::String(String::new()));
            strip_null(&mut schema);
            json!({
                "name": name,
                "in": "query",
                "required": required.contains(&name.as_str()),
                "description": description,
                "schema": schema,
            })
        })
        .collect()
}

/// A query value is never `null`: drop the `null` branch `Option<T>` adds to a schema.
fn strip_null(schema: &mut Value) {
    let Some(o) = schema.as_object_mut() else {
        return;
    };
    if let Some(Value::Array(types)) = o.get_mut("type") {
        types.retain(|t| t != "null");
        if types.len() == 1 {
            let only = types.remove(0);
            o.insert("type".to_owned(), only);
        }
    }
    if let Some(Value::Array(any)) = o.remove("anyOf") {
        let mut rest: Vec<Value> = any.into_iter().filter(|b| b["type"] != "null").collect();
        if rest.len() == 1 {
            if let Some(Value::Object(inner)) = rest.pop() {
                for (k, v) in inner {
                    o.entry(k).or_insert(v);
                }
            }
        } else {
            o.insert("anyOf".to_owned(), Value::Array(rest));
        }
    }
}

/// The spec of the operation `id`, or `None` for an operation the document describes by id,
/// summary and scope only (the native `/v1` operations).
pub(crate) fn spec(id: &str) -> Option<Spec> {
    scrape::spec(id)
        .or_else(|| crawl::spec(id))
        .or_else(|| map::spec(id))
        .or_else(|| search::spec(id))
        .or_else(|| extract::spec(id))
        .or_else(|| agent::spec(id))
        .or_else(|| monitor::spec(id))
        .or_else(|| parse::spec(id))
        .or_else(|| team::spec(id))
        .or_else(|| watch::spec(id))
}
