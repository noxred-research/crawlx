#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Drift tests of the generated OpenAPI schemas of the Firecrawl facade (`GET /v1/openapi.json`).
//!
//! * **routes**: every `(method, path)` the router mounts under `/compat/firecrawl/v2` and
//!   `/v0/health/` is documented and every documented one is mounted (source scan of the
//!   `.route(...)` calls plus a probe of the live router with every method);
//! * **structure**: every `$ref` resolves, operation ids are unique, path parameters are declared,
//!   every component is a valid JSON Schema 2020-12 document and is referenced;
//! * **requests**: the property set of each request schema equals what the real parser reads
//!   (examples that cover the schema are accepted by the real handler or parser, a key absent from
//!   the schema is reported, every documented key is consumed by the parser, and the key lists in
//!   the parsers' sources are the schema's);
//! * **responses**: real responses of the facade (a real worker for scrape, crawl, batch and map;
//!   mocked backends for the rest) validate against the generated response schemas.
mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

#[path = "openapi_schemas/drift.rs"]
mod drift;
#[path = "openapi_schemas/flows.rs"]
mod flows;
#[path = "openapi_schemas/query.rs"]
mod query;
#[path = "openapi_schemas/rigs.rs"]
mod rigs;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use common::Env;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::intel::exchange::{Capability, MockExchange, Toolkit};
use crawlx_api::intel::search::{ImageHit, MockSearch, NewsHit, SearchResults, WebHit};
use crawlx_api::intel::tools::MockPageTools;
use crawlx_api::intel::webhook::JobWebhookSink;
use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookTransport};
use crawlx_api::{AppState, Repos, Scope};
use crawlx_model::llm::{LlmCall, LlmError, LlmExtractor, MockLlm};
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::{DeliveryBuffer, MemoryArtifactStore, MemoryStore};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const V2: &str = "/compat/firecrawl/v2";
const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];
/// A path value that no resource has.
const UNKNOWN_ID: &str = "00000000-0000-7000-8000-000000000000";

// ---- the document -----------------------------------------------------------------------------

fn doc() -> Value {
    crawlx_api::openapi::document()
}

fn is_facade(path: &str) -> bool {
    path.starts_with(V2) || path.starts_with("/v0/health/")
}

/// Every `(method, path, operation)` of the document.
fn operations(doc: &Value) -> Vec<(String, String, &Value)> {
    let mut out = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            out.push((method.clone(), path.clone(), op));
        }
    }
    out
}

fn facade_operations(doc: &Value) -> Vec<(String, String, &Value)> {
    operations(doc)
        .into_iter()
        .filter(|(_, p, _)| is_facade(p))
        .collect()
}

fn op_by_id<'a>(doc: &'a Value, id: &str) -> (String, String, &'a Value) {
    operations(doc)
        .into_iter()
        .find(|(_, _, op)| op["operationId"] == id)
        .unwrap_or_else(|| panic!("no operation {id}"))
}

/// The component a `$ref` names.
fn deref_one<'a>(doc: &'a Value, reference: &str) -> &'a Value {
    let name = reference
        .strip_prefix("#/components/schemas/")
        .unwrap_or_else(|| panic!("$ref {reference} is not a component"));
    let target = &doc["components"]["schemas"][name];
    assert!(!target.is_null(), "dangling $ref {reference}");
    target
}

/// `schema` with its `$ref` chain followed.
fn resolve<'a>(doc: &'a Value, schema: &'a Value) -> &'a Value {
    let mut cur = schema;
    for _ in 0..16 {
        match cur.get("$ref").and_then(Value::as_str) {
            Some(r) => cur = deref_one(doc, r),
            None => return cur,
        }
    }
    panic!("$ref cycle at {schema}");
}

/// A validator for `schema` that can reach the document's components.
fn validator(doc: &Value, schema: &Value) -> jsonschema::Validator {
    let mut root = schema.clone();
    root.as_object_mut()
        .expect("an object schema")
        .insert("components".to_owned(), doc["components"].clone());
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&root)
        .unwrap_or_else(|e| panic!("the schema does not compile: {e}\n{schema}"))
}

fn errors_of(v: &jsonschema::Validator, instance: &Value) -> Vec<String> {
    v.iter_errors(instance)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect()
}

/// The JSON schema of `responses.<status>` of an operation.
fn response_schema(op: &Value, status: &str) -> Option<Value> {
    op["responses"][status]["content"]["application/json"]
        .get("schema")
        .cloned()
}

/// The schema of the JSON (or multipart) request body of an operation.
fn request_schema(op: &Value) -> Option<(String, Value)> {
    let content = op["requestBody"]["content"].as_object()?;
    let (media, body) = content.iter().next()?;
    Some((media.clone(), body["schema"].clone()))
}

// ---- the router -------------------------------------------------------------------------------

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn send(
    app: &Router,
    key: Option<&str>,
    method: &Method,
    uri: &str,
    content_type: Option<&str>,
    extra: &[(&str, &str)],
    body: Vec<u8>,
) -> Reply {
    let mut b = Request::builder().method(method.clone()).uri(uri);
    if let Some(k) = key {
        b = b.header("authorization", format!("Bearer {k}"));
    }
    if let Some(c) = content_type {
        b = b.header("content-type", c);
    }
    for (n, v) in extra {
        b = b.header(*n, *v);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024).await.unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        },
    }
}

async fn json_call(
    app: &Router,
    key: Option<&str>,
    method: Method,
    uri: &str,
    body: Option<&Value>,
) -> Reply {
    send(
        app,
        key,
        &method,
        uri,
        body.map(|_| "application/json"),
        &[],
        body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
    )
    .await
}

/// A path with every `{param}` filled with something no resource has.
fn fill(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let end = rest[i..].find('}').unwrap() + i;
        let name = &rest[i + 1..end];
        out.push_str(if name == "paperId" {
            "arxiv:2401.00001"
        } else {
            UNKNOWN_ID
        });
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// `{param}` names collapsed, so `{jobId}` and `{job_id}` compare equal.
fn normalize(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        out.push_str("{}");
        rest = &rest[rest[i..].find('}').unwrap() + i + 1..];
    }
    out.push_str(rest);
    out
}

/// The `(method, path)` pairs of the `.route(...)` calls of a source file (code before its
/// `#[cfg(test)]` module).
fn route_calls(src: &str) -> Vec<(String, String)> {
    let src = src.split("#[cfg(test)]").next().unwrap();
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find(".route(") {
        let after = &rest[i + ".route(".len()..];
        let mut depth = 1_i32;
        let mut in_str = false;
        let mut end = after.len();
        for (j, c) in after.char_indices() {
            match c {
                '"' => in_str = !in_str,
                '(' if !in_str => depth += 1,
                ')' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        end = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &after[..end];
        let q1 = body.find('"').expect("a route path literal");
        let q2 = body[q1 + 1..].find('"').unwrap() + q1 + 1;
        let path = &body[q1 + 1..q2];
        let handlers = &body[q2 + 1..];
        for m in METHODS {
            let pat = format!("{m}(");
            let mut from = 0;
            while let Some(k) = handlers[from..].find(&pat) {
                let pos = from + k;
                let prev = handlers[..pos].chars().last();
                if !prev.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    out.push((m.to_owned(), path.to_owned()));
                }
                from = pos + pat.len();
            }
        }
        rest = &after[end..];
    }
    out
}

/// Every route the router mounts, from the sources of the route modules.
fn mounted_in_source() -> BTreeSet<(String, String)> {
    [
        include_str!("../src/routes/mod.rs"),
        include_str!("../src/routes/compat_agent.rs"),
        include_str!("../src/routes/compat_crawl.rs"),
        include_str!("../src/routes/compat_extract.rs"),
        include_str!("../src/routes/compat_map.rs"),
        include_str!("../src/routes/compat_monitor.rs"),
        include_str!("../src/routes/compat_parse.rs"),
        include_str!("../src/routes/compat_scrape.rs"),
        include_str!("../src/routes/compat_search.rs"),
        include_str!("../src/routes/compat_team.rs"),
        include_str!("../src/routes/compat_ws.rs"),
    ]
    .into_iter()
    .flat_map(route_calls)
    .filter(|(_, p)| is_facade(p))
    .map(|(m, p)| (m, normalize(&p)))
    .collect()
}

#[test]
fn the_document_lists_exactly_the_routes_the_router_mounts() {
    let doc = doc();
    let documented: BTreeSet<(String, String)> = facade_operations(&doc)
        .into_iter()
        .map(|(m, p, _)| (m, normalize(&p)))
        .collect();
    let mounted = mounted_in_source();
    let from_list: BTreeSet<(String, String)> = crawlx_api::openapi::operations()
        .into_iter()
        .filter(|(_, p)| is_facade(p))
        .map(|(m, p)| (m.to_owned(), normalize(p)))
        .collect();
    assert_eq!(documented, from_list, "document() and operations() disagree");
    let undocumented: Vec<_> = mounted.difference(&documented).collect();
    let unmounted: Vec<_> = documented.difference(&mounted).collect();
    assert!(
        undocumented.is_empty() && unmounted.is_empty(),
        "mounted but not documented: {undocumented:?}\ndocumented but not mounted: {unmounted:?}"
    );
    assert!(
        documented.len() >= 51,
        "49 facade operations and 2 health probes at least"
    );
}

#[tokio::test]
async fn every_documented_route_answers_and_no_other_method_is_mounted() {
    let env = common::env();
    let doc = doc();
    let facade = facade_operations(&doc);
    let documented: BTreeSet<(String, String)> =
        facade.iter().map(|(m, p, _)| (m.clone(), p.clone())).collect();
    let probe = |method: &str, path: &str| {
        let m = Method::from_bytes(method.to_ascii_uppercase().as_bytes()).unwrap();
        let env = &env;
        let uri = fill(path);
        async move {
            // an invalid body for every method that may carry one
            let body = if matches!(m, Method::POST | Method::PUT | Method::PATCH) {
                Some(json!([]))
            } else {
                None
            };
            json_call(&env.app, Some(&env.key), m, &uri, body.as_ref()).await
        }
    };
    for (method, path) in &documented {
        let r = probe(method, path).await;
        assert!(
            r.status != StatusCode::METHOD_NOT_ALLOWED
                && !(r.status == StatusCode::NOT_FOUND && r.body["error"] == "route not found"),
            "{method} {path} is documented but not mounted: {} {}",
            r.status,
            r.body
        );
    }
    let paths: BTreeSet<&String> = documented.iter().map(|(_, p)| p).collect();
    for path in paths {
        for method in METHODS {
            if documented.contains(&(method.to_owned(), path.clone())) {
                continue;
            }
            let r = probe(method, path).await;
            assert_eq!(
                r.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path} is mounted but not documented: {}",
                r.body
            );
        }
    }
}

#[test]
fn every_facade_operation_has_request_and_response_schemas() {
    let doc = doc();
    // the operations whose request carries no body
    const NO_BODY: [&str; 1] = ["runMonitor"];
    let facade = facade_operations(&doc);
    let (mut with_request, mut needing_request, mut with_response) = (0, 0, 0);
    for (method, path, op) in &facade {
        let id = op["operationId"].as_str().unwrap();
        let carries_body = matches!(method.as_str(), "post" | "put" | "patch") && !NO_BODY.contains(&id);
        match (carries_body, request_schema(op)) {
            (true, Some((media, schema))) => {
                assert!(
                    media == "application/json" || media == "multipart/form-data",
                    "{id}: {media}"
                );
                assert!(schema.is_object(), "{id}: no request schema");
                with_request += 1;
                needing_request += 1;
            }
            (true, None) => panic!("{id} ({method} {path}) has no request schema"),
            (false, None) => {}
            (false, Some(_)) => panic!("{id} ({method} {path}) documents a body it does not read"),
        }
        let success: Vec<&String> = op["responses"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|s| s.starts_with('2'))
            .collect();
        assert!(!success.is_empty(), "{id} has no 2xx response");
        for s in success {
            assert!(
                response_schema(op, s).is_some_and(|x| x.is_object()),
                "{id}: the {s} response has no schema"
            );
        }
        with_response += 1;
    }
    eprintln!(
        "openapi: {with_request}/{needing_request} body operations with a request schema, \
         {with_response}/{} operations with a 2xx response schema",
        facade.len()
    );
    assert!(facade.len() >= 51);
    assert_eq!(with_request, needing_request);
}

// ---- structure --------------------------------------------------------------------------------

/// Every `$ref` string of `v`.
fn refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "$ref" {
                    if let Some(s) = x.as_str() {
                        out.push(s.to_owned());
                    }
                } else {
                    refs(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| refs(x, out)),
        _ => {}
    }
}

#[test]
fn the_document_is_a_well_formed_openapi_31_document() {
    let doc = doc();
    assert!(doc["openapi"].as_str().unwrap().starts_with("3.1"));

    // every $ref resolves into components.schemas
    let mut all = Vec::new();
    refs(&doc, &mut all);
    assert!(!all.is_empty());
    for r in &all {
        deref_one(&doc, r);
    }

    // operation ids are unique; every operation declares its path parameters
    let mut ids = BTreeSet::new();
    for (method, path, op) in operations(&doc) {
        let id = op["operationId"]
            .as_str()
            .unwrap_or_else(|| panic!("{method} {path}: no id"));
        assert!(ids.insert(id.to_owned()), "operation id {id} is used twice");
        assert!(op["responses"].as_object().is_some_and(|r| !r.is_empty()), "{id}");
        let params = op["parameters"].as_array().unwrap();
        let declared: BTreeSet<&str> = params
            .iter()
            .filter(|p| p["in"] == "path")
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        let mut templated = BTreeSet::new();
        let mut rest = path.as_str();
        while let Some(i) = rest.find('{') {
            let end = rest[i..].find('}').unwrap() + i;
            templated.insert(&rest[i + 1..end]);
            rest = &rest[end + 1..];
        }
        assert_eq!(declared, templated, "{id}: path parameters of {path}");
        let mut seen = BTreeSet::new();
        for p in params {
            assert!(
                seen.insert((p["in"].as_str().unwrap(), p["name"].as_str().unwrap())),
                "{id}: parameter {p} is declared twice"
            );
            if p["in"] == "path" {
                assert_eq!(p["required"], true, "{id}: {p}");
            }
            assert!(p["schema"].is_object(), "{id}: parameter {p} has no schema");
            assert!(
                jsonschema::draft202012::meta::is_valid(&p["schema"]),
                "{id}: the schema of {p} is invalid"
            );
        }
        for (status, resp) in op["responses"].as_object().unwrap() {
            let code: u16 = status.parse().unwrap_or_else(|_| panic!("{id}: status {status}"));
            assert!((100..600).contains(&code), "{id}: status {status}");
            assert!(resp["description"].is_string(), "{id}: {status}");
        }
    }

    // every component is a valid schema document that compiles and is referenced
    let components = doc["components"]["schemas"].as_object().unwrap();
    for (name, schema) in components {
        assert!(
            jsonschema::draft202012::meta::is_valid(schema),
            "component {name} is not a valid JSON Schema 2020-12 document: {schema}"
        );
        validator(&doc, &json!({ "$ref": format!("#/components/schemas/{name}") }));
    }
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<String> = Vec::new();
    refs(&doc["paths"], &mut frontier);
    while let Some(r) = frontier.pop() {
        let name = r.strip_prefix("#/components/schemas/").unwrap().to_owned();
        if referenced.insert(name.clone()) {
            refs(&components[&name], &mut frontier);
        }
    }
    let unused: Vec<&String> = components.keys().filter(|k| !referenced.contains(*k)).collect();
    assert!(unused.is_empty(), "components no operation reaches: {unused:?}");
    assert!(components.contains_key("FacadeError"));
}

#[test]
fn the_document_is_deterministic() {
    let a = serde_json::to_string(&doc()).unwrap();
    let b = serde_json::to_string(&doc()).unwrap();
    assert_eq!(a, b);
    // object keys are sorted (BTreeMap order), so the rendering does not depend on hash seeds
    fn sorted(v: &Value) {
        match v {
            Value::Object(m) => {
                let keys: Vec<&String> = m.keys().collect();
                let mut s = keys.clone();
                s.sort();
                assert_eq!(keys, s);
                m.values().for_each(sorted);
            }
            Value::Array(a) => a.iter().for_each(sorted),
            _ => {}
        }
    }
    sorted(&serde_json::from_str::<Value>(&a).unwrap());
}

#[tokio::test]
async fn the_document_endpoint_serves_the_same_document_without_authentication() {
    let env = common::env();
    let r = json_call(&env.app, None, Method::GET, "/v1/openapi.json", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, doc());
}
