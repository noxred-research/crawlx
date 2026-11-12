#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authored selector and feed corpus: exact node-set order, typed failures, one-over resource
//! limits and zero document or network resolution for the `selector` family, and the exact
//! admitted URL set with provenance, scope and budgets for the `feed` family.
//!
//! Both families live in `tests/corpus/` next to the other families and are listed in
//! `manifest.selector.json` and `manifest.feed.json`. Every gold file holds an `expectedText`
//! of one line per expected item and one labeled UTF-8 byte span per line.
//!
//! # Selector family
//!
//! The page is the case input; the rules are in the manifest `params`. `params.mode` is one of
//!
//! * `rules`: each rule is `{id, kind, expression | repeat, [context], [namespaces], [empty]}`
//!   and is evaluated on a fresh document index. Gold spans are labeled with the rule id, one
//!   span per result item in document order. A node-set result is rendered as the whitespace
//!   collapsed string value of each node; a string result as a JSON string literal; a number
//!   as its XPath string; a boolean as `true` or `false`; a failure as `error:<kind>`. A rule
//!   with no gold span declares `"empty": true` and must select nothing. `repeat` builds an
//!   expression as `prefix + unit * count + suffix` so limit fixtures stay readable.
//! * `item`: an item loader recipe (`itemLoader`, optional pinned local `schema`) evaluated
//!   against the page. Gold spans are labeled with the field name and hold `name=<json>` in
//!   recipe order; `expect` lists the item validity and the quality of every field.
//! * `compile`: variants of a recipe or a local schema that are only compiled; each gold line
//!   is `ok` or `error:<kind>` labeled with the variant id.
//! * `policy`: variants of a selector policy resolved on the page; gold lines are the selected
//!   (`<id>.include`) and removed (`<id>.exclude`) elements, or `ok` or an error line.
//!
//! The placeholder `{{probe}}` in a page, a rule, a schema or a gold line stands for the origin
//! of a listening loopback socket; the suite fails if anything connects to it.
//!
//! # Feed family
//!
//! The feed or sitemap document is the case input; `params` holds the seed URL, the scope, the
//! discovery policy, the format (`feed`, `sitemap`, `sitemap-traversal`, `sitemap-gzip`),
//! further documents a traversal may request (`documents`) and the expected outcome class.
//! The pure parsers only propose references. This suite applies the crawl scope to every
//! proposal, requests further documents only when scope admits them, and records each request.
//! Gold lines are the admitted URLs in processing order, labeled with their provenance:
//! `item` (RSS, RDF or JSON item link), `alternate` (Atom alternate link), `media`, `read_more`
//! (entry-level next link), `next` (feed pagination), `page` and `variant` (sitemap entry and
//! its language alternate), `request` (a further document that was requested), `transport` and
//! `error`.

mod corpus_support;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::TcpListener;

use base64::Engine as _;
use corpus_support::*;
use crawlx_core::{
    config::Scope,
    discovery::{DiscoveryErrorV1, SourceDiscoveryPolicyV1},
    hash::Digest,
    selectors::{
        ItemLoaderV1, SelectorPolicyV1, SelectorV1, MAX_AST_NODES, MAX_EXPRESSION_BYTES, MAX_OPERATIONS,
        MAX_SELECTED,
    },
};
use crawlx_extract::{
    item_loader::CompiledItemLoader,
    xpath::{CompiledSelector, SelectorDocument, SelectorError, XPathValue},
};
use crawlx_url::{
    error::UrlError,
    feed::{parse_feed, FeedError, FeedKind, XmlFeedStream},
    scope::{ScopeDecision, ScopeFilter},
    sitemap::{PendingSitemap, SitemapKind, SitemapParser, SitemapTraversal, MAX_DEPTH},
};
use scraper::Html;
use serde_json::{json, Value};
use url::Url;

type Line = (String, String);

// ------------------------------------------------------------------------------------------
// shared helpers
// ------------------------------------------------------------------------------------------

/// A listening loopback socket. Pages, schemas and feeds point at it; if anything under test
/// opened a connection, `assert_untouched` fails. It never leaves the machine.
struct Probe {
    listener: TcpListener,
    origin: String,
}

impl Probe {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        Self { listener, origin }
    }

    fn apply(&self, text: &str) -> String {
        text.replace("{{probe}}", &self.origin)
    }

    fn params(&self, case: &Case) -> Value {
        serde_json::from_str(&self.apply(&case.entry.params.to_string())).unwrap()
    }

    fn assert_untouched(&self, what: &str) {
        match self.listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("{what}: a connection reached the probe socket: {other:?}"),
        }
    }
}

fn gold_lines(case: &Case, probe: &Probe) -> Vec<Line> {
    case.gold
        .spans
        .iter()
        .map(|span| {
            (
                span.label.clone(),
                probe.apply(&case.gold.expected_text[span.start..span.end]),
            )
        })
        .collect()
}

fn as_usize(value: u64) -> usize {
    usize::try_from(value).unwrap()
}

fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| json_eq(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| json_eq(v, w)))
        }
        _ => a == b,
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|list| list.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

/// Every gold file is a sorted, disjoint list of non-empty UTF-8 byte ranges into `expectedText`
/// with exactly one span per line.
fn assert_gold_shape(case: &Case) {
    let id = &case.entry.id;
    let Gold {
        expected_text, spans, ..
    } = &case.gold;
    assert!(!spans.is_empty(), "{id}: no gold span");
    let mut expected_start = 0;
    for span in spans {
        assert!(span.start < span.end && span.end <= expected_text.len(), "{id}");
        assert!(expected_text.is_char_boundary(span.start), "{id}");
        assert!(expected_text.is_char_boundary(span.end), "{id}");
        assert_eq!(span.start, expected_start, "{id}: gold spans cover one line each");
        assert!(!expected_text[span.start..span.end].contains('\n'), "{id}");
        expected_start = span.end + 1;
    }
    assert_eq!(
        expected_start,
        expected_text.len() + 1,
        "{id}: trailing text without a span"
    );
}

// ------------------------------------------------------------------------------------------
// selector family
// ------------------------------------------------------------------------------------------

fn selector_cases() -> Vec<Case> {
    cases_of(&["selector"])
}

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn number_text(n: f64) -> String {
    if n.is_nan() {
        "NaN".to_owned()
    } else if n.is_infinite() {
        if n > 0.0 { "Infinity" } else { "-Infinity" }.to_owned()
    } else if n == 0.0 {
        "0".to_owned()
    } else {
        format!("{n}")
    }
}

fn selector_error(error: &SelectorError) -> String {
    let kind = match error {
        SelectorError::Syntax => "Syntax".to_owned(),
        SelectorError::UnsupportedFunction => "UnsupportedFunction".to_owned(),
        SelectorError::Namespace => "Namespace".to_owned(),
        SelectorError::NodeSetRequired => "NodeSetRequired".to_owned(),
        SelectorError::Budget(what) => format!("Budget({what})"),
        SelectorError::Schema(what) => format!("Schema({what})"),
        SelectorError::Unsupported(what) => format!("Unsupported({what})"),
        SelectorError::Policy(_) => "Policy".to_owned(),
        SelectorError::Regex(_) => "Regex".to_owned(),
        other => format!("{other:?}"),
    };
    format!("error:{kind}")
}

fn rule_expression(rule: &Value) -> String {
    if let Some(repeat) = rule.get("repeat") {
        let text = |key: &str| repeat.get(key).and_then(Value::as_str).unwrap_or("").to_owned();
        let count = as_usize(repeat["count"].as_u64().unwrap());
        format!(
            "{}{}{}",
            text("prefix"),
            text("unit").repeat(count),
            text("suffix")
        )
    } else {
        rule["expression"].as_str().unwrap().to_owned()
    }
}

fn rule_selector(rule: &Value) -> SelectorV1 {
    serde_json::from_value(json!({"kind": rule["kind"], "expression": rule_expression(rule)})).unwrap()
}

fn namespaces_of(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

/// One rule on a fresh index of the page: the rendered result items, or one error line.
fn evaluate_rule(html: &Html, rule: &Value, case_namespaces: &BTreeMap<String, String>) -> Vec<String> {
    let selector = match CompiledSelector::compile(&rule_selector(rule)) {
        Ok(selector) => selector,
        Err(error) => return vec![selector_error(&error)],
    };
    let mut doc = match SelectorDocument::new(html) {
        Ok(doc) => doc,
        Err(error) => return vec![selector_error(&error)],
    };
    let namespaces = rule
        .get("namespaces")
        .map_or_else(|| case_namespaces.clone(), |own| namespaces_of(Some(own)));
    let context = match rule.get("context").and_then(Value::as_str) {
        Some(expression) => {
            let locate = CompiledSelector::xpath(expression).unwrap();
            let XPathValue::Nodes(nodes) = doc.evaluate(&locate, &BTreeMap::new()).unwrap() else {
                panic!("context selector must select nodes");
            };
            nodes[0]
        }
        None => 0,
    };
    let value = match doc.evaluate_in(&selector, context, &namespaces) {
        Ok(value) => value,
        Err(error) => return vec![selector_error(&error)],
    };
    match value {
        XPathValue::Nodes(nodes) => nodes
            .iter()
            .map(|node| match doc.string_value(*node) {
                Ok(text) => collapse(&text),
                Err(error) => selector_error(&error),
            })
            .collect(),
        XPathValue::String(text) => vec![serde_json::to_string(&text).unwrap()],
        XPathValue::Number(n) => vec![number_text(n)],
        XPathValue::Boolean(b) => vec![b.to_string()],
        other => panic!("unexpected selector result {other:?}"),
    }
}

fn pin_schema(spec: &mut ItemLoaderV1, schema: Value) {
    let key = Digest::of("crawlx.item.schema.v1", &serde_json::to_vec(&schema).unwrap()).to_hex();
    spec.schema = Some(key.clone());
    spec.schemas.insert(key, schema);
}

fn plain_field(name: &str) -> Value {
    json!({"name": name, "selectors": [{"kind": "css", "expression": "p"}],
        "extraction": {"kind": "text"}, "cardinality": "one"})
}

/// Recipe or schema built from a limit description, so one-over fixtures stay a few bytes.
fn generated(description: &Value) -> (Value, Option<Value>) {
    let (key, count) = description
        .as_object()
        .and_then(|map| map.iter().next())
        .map(|(key, value)| (key.as_str(), as_usize(value.as_u64().unwrap())))
        .unwrap();
    let mut loader = json!({"version": 1, "fields": []});
    let mut schema = None;
    match key {
        "fields" => {
            loader["fields"] = Value::Array((0..count).map(|n| plain_field(&format!("f{n}"))).collect());
        }
        "selectors" => {
            let mut field = plain_field("f");
            field["selectors"] = Value::Array(vec![json!({"kind": "css", "expression": "p"}); count]);
            loader["fields"] = json!([field]);
        }
        "transforms" | "inputProcessors" => {
            let mut field = plain_field("f");
            field[key] = Value::Array(vec![json!({"kind": "trim"}); count]);
            loader["fields"] = json!([field]);
        }
        "nesting" => {
            let mut inner = plain_field("leaf");
            for level in (0..count).rev() {
                inner = json!({"name": format!("g{level}"), "selectors": [{"kind": "css", "expression": "div"}],
                    "extraction": {"kind": "group"}, "cardinality": "many", "fields": [inner]});
            }
            loader["fields"] = json!([inner]);
        }
        "namespaces" => {
            loader["namespaces"] = Value::Object(
                (0..count)
                    .map(|n| (format!("p{n}"), Value::String(format!("urn:corpus:ns{n}"))))
                    .collect(),
            );
        }
        "defaultBytes" => {
            let mut field = plain_field("f");
            // The serialized default, quotes included, is exactly `count` bytes.
            field["default"] = Value::String("x".repeat(count - 2));
            loader["fields"] = json!([field]);
        }
        "limit" => {
            let mut field = plain_field("f");
            field["transforms"] = json!([{"kind": "limit", "count": count}]);
            loader["fields"] = json!([field]);
        }
        "separator" => {
            let mut field = plain_field("f");
            field["transforms"] = json!([{"kind": "join", "separator": "s".repeat(count)}]);
            loader["fields"] = json!([field]);
        }
        "schemaChain" => {
            let mut defs = serde_json::Map::new();
            for n in 0..count {
                let body = if n + 1 == count {
                    json!({"type": "object"})
                } else {
                    json!({"$ref": format!("#/$defs/d{}", n + 1)})
                };
                defs.insert(format!("d{n}"), body);
            }
            schema = Some(json!({"$defs": defs, "$ref": "#/$defs/d0"}));
        }
        "schemaAllOf" => {
            schema = Some(json!({"allOf": vec![Value::Bool(true); count]}));
        }
        other => panic!("unknown generator {other}"),
    }
    (loader, schema)
}

fn compile_variant(variant: &Value) -> String {
    let (loader, schema) = match variant.get("generate") {
        Some(description) => generated(description),
        None => (
            variant
                .get("loader")
                .cloned()
                .unwrap_or_else(|| json!({"version": 1})),
            variant.get("schema").cloned(),
        ),
    };
    let mut spec: ItemLoaderV1 = serde_json::from_value(loader).unwrap();
    if let Some(schema) = schema {
        pin_schema(&mut spec, schema);
    }
    match CompiledItemLoader::compile(&spec) {
        Ok(_) => "ok".to_owned(),
        Err(error) => selector_error(&error),
    }
}

fn policy_variant(html: &Html, variant: &Value) -> Vec<Line> {
    let id = variant["id"].as_str().unwrap().to_owned();
    let policy_json = match variant.get("generate") {
        Some(description) => {
            let (key, count) = description
                .as_object()
                .and_then(|map| map.iter().next())
                .map(|(key, value)| (key.as_str(), as_usize(value.as_u64().unwrap())))
                .unwrap();
            let footer = json!({"kind": "css", "expression": "footer"});
            match key {
                "include" => json!({"include": vec![footer; count]}),
                "namespaces" => json!({"include": [footer],
                    "namespaces": (0..count).map(|n| (format!("p{n}"), format!("urn:corpus:ns{n}"))).collect::<BTreeMap<_, _>>()}),
                "expressionBytes" => json!({"include": [{"kind": "xpath", "expression": "x".repeat(count)}]}),
                other => panic!("unknown generator {other}"),
            }
        }
        None => variant["policy"].clone(),
    };
    let policy: SelectorPolicyV1 = serde_json::from_value(policy_json).unwrap();
    let mut doc = SelectorDocument::new(html).unwrap();
    let selected = match doc.select_policy(&policy) {
        Ok(selected) => selected,
        Err(error) => return vec![(id, selector_error(&error))],
    };
    let mut out = Vec::new();
    for (suffix, set) in [("include", &selected.include), ("exclude", &selected.exclude)] {
        let mut nodes: Vec<usize> = set.iter().map(|id| doc.index_of(*id).unwrap()).collect();
        nodes.sort_unstable();
        for node in nodes {
            out.push((
                format!("{id}.{suffix}"),
                collapse(&doc.string_value(node).unwrap()),
            ));
        }
    }
    if out.is_empty() {
        out.push((id, "ok".to_owned()));
    }
    out
}

fn item_lines(case: &Case, params: &Value, html: &Html) -> Vec<Line> {
    let mut spec: ItemLoaderV1 = serde_json::from_value(params["itemLoader"].clone()).unwrap();
    if let Some(schema) = params.get("schema") {
        pin_schema(&mut spec, schema.clone());
    }
    let compiled = match CompiledItemLoader::compile(&spec) {
        Ok(compiled) => compiled,
        Err(error) => return vec![("compile".to_owned(), selector_error(&error))],
    };
    let mut doc = SelectorDocument::new(html).unwrap();
    let base = Url::parse(&case.entry.page_url).unwrap();
    let outcome = match compiled.load(&mut doc, &base) {
        Ok(outcome) => outcome,
        Err(error) => return vec![("load".to_owned(), selector_error(&error))],
    };
    let expect = &params["expect"];
    let id = &case.entry.id;
    assert_eq!(
        outcome.valid,
        expect["valid"].as_bool().unwrap(),
        "{id}: item validity"
    );
    assert_eq!(
        outcome.schema_valid,
        expect.get("schemaValid").and_then(Value::as_bool),
        "{id}: schema validity"
    );
    let wanted = expect["quality"].as_object().unwrap();
    assert_eq!(
        outcome.fields.len(),
        wanted.len(),
        "{id}: every field declares its quality"
    );
    let mut lines = Vec::new();
    for field in &outcome.fields {
        assert_eq!(
            serde_json::to_value(field.quality).unwrap(),
            wanted[&field.name],
            "{id}: quality of {}",
            field.name
        );
        if let Some(value) = &field.value {
            lines.push((
                field.name.clone(),
                format!("{}={}", field.name, serde_json::to_string(value).unwrap()),
            ));
        }
    }
    lines
}

fn selector_lines(case: &Case, probe: &Probe) -> Vec<Line> {
    let params = probe.params(case);
    let html = Html::parse_document(&probe.apply(&case.html));
    match params["mode"].as_str().unwrap() {
        "rules" => {
            let case_namespaces = namespaces_of(params.get("namespaces"));
            let mut lines = Vec::new();
            for rule in params["rules"].as_array().unwrap() {
                let id = rule["id"].as_str().unwrap();
                let items = evaluate_rule(&html, rule, &case_namespaces);
                // Evaluation is a pure function of the page and the rule.
                assert_eq!(
                    items,
                    evaluate_rule(&html, rule, &case_namespaces),
                    "{}: {id} is not stable",
                    case.entry.id
                );
                assert_eq!(
                    items.is_empty(),
                    rule.get("empty").and_then(Value::as_bool).unwrap_or(false),
                    "{}: rule {id} must declare an empty result exactly when it selects nothing",
                    case.entry.id
                );
                lines.extend(items.into_iter().map(|item| (id.to_owned(), item)));
            }
            lines
        }
        "item" => item_lines(case, &params, &html),
        "compile" => params["variants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|variant| {
                (
                    variant["id"].as_str().unwrap().to_owned(),
                    compile_variant(variant),
                )
            })
            .collect(),
        "policy" => params["variants"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|variant| policy_variant(&html, variant))
            .collect(),
        other => panic!("{}: unknown mode {other}", case.entry.id),
    }
}

#[test]
fn selector_gold_is_one_span_per_line() {
    for case in selector_cases() {
        assert_gold_shape(&case);
        assert!(
            case.entry.page_url.starts_with("https://corpus.test/"),
            "{}",
            case.entry.id
        );
    }
}

#[test]
fn selector_cases_match_gold_exactly_and_open_no_connection() {
    let probe = Probe::new();
    for case in selector_cases() {
        let actual = selector_lines(&case, &probe);
        let gold = gold_lines(&case, &probe);
        if case.entry.params["mode"] == "item" {
            // Items compare as JSON values: `2` and `2.0` are one number.
            assert_eq!(actual.len(), gold.len(), "{}: item field count", case.entry.id);
            for ((name, text), (gold_name, gold_text)) in actual.iter().zip(&gold) {
                assert_eq!(name, gold_name, "{}", case.entry.id);
                let (_, actual_json) = text.split_once('=').unwrap();
                let (field, gold_json) = gold_text.split_once('=').unwrap();
                assert_eq!(field, gold_name, "{}", case.entry.id);
                let actual_value: Value = serde_json::from_str(actual_json).unwrap();
                let gold_value: Value = serde_json::from_str(gold_json).unwrap();
                assert!(
                    json_eq(&actual_value, &gold_value),
                    "{}: {name}: {actual_json} != {gold_json}",
                    case.entry.id
                );
            }
        } else {
            assert_eq!(actual, gold, "{}", case.entry.id);
        }
    }
    probe.assert_untouched("selector family");
}

fn has_call(expressions: &[String], name: &str) -> bool {
    let call = format!("{name}(");
    expressions.iter().any(|expression| {
        expression.match_indices(&call).any(|(at, _)| {
            expression[..at]
                .chars()
                .next_back()
                .is_none_or(|before| !(before.is_ascii_alphanumeric() || before == '-' || before == '_'))
        })
    })
}

fn walk_fields<'a>(fields: &'a Value, out: &mut Vec<&'a Value>) {
    for field in fields.as_array().into_iter().flatten() {
        out.push(field);
        walk_fields(&field["fields"], out);
    }
}

#[test]
fn selector_family_covers_every_axis_function_transform_and_cardinality() {
    let cases = selector_cases();
    assert!(
        cases.len() >= 40,
        "{} selector cases, plan minimum 40",
        cases.len()
    );
    let ids: BTreeSet<&str> = cases.iter().map(|c| c.entry.id.as_str()).collect();
    assert_eq!(ids.len(), cases.len());
    assert!(ids.iter().all(|id| id.starts_with('s')));

    let mut xpath = Vec::new();
    let mut kinds = BTreeSet::new();
    let mut modes = BTreeSet::new();
    let mut transforms = BTreeSet::new();
    let mut cardinalities = BTreeSet::new();
    for case in &cases {
        let params = &case.entry.params;
        modes.insert(params["mode"].as_str().unwrap().to_owned());
        for rule in params["rules"].as_array().into_iter().flatten() {
            kinds.insert(rule["kind"].as_str().unwrap().to_owned());
            if rule["kind"] == "xpath" {
                xpath.push(rule_expression(rule));
            }
        }
        let mut fields = Vec::new();
        walk_fields(&params["itemLoader"]["fields"], &mut fields);
        for field in fields {
            for selector in field["selectors"].as_array().unwrap() {
                if selector["kind"] == "xpath" {
                    xpath.push(selector["expression"].as_str().unwrap().to_owned());
                }
                kinds.insert(format!("item-{}", selector["kind"].as_str().unwrap()));
            }
            for list in ["transforms", "inputProcessors"] {
                for transform in field[list].as_array().into_iter().flatten() {
                    transforms.insert(transform["kind"].as_str().unwrap().to_owned());
                }
            }
            if field["extraction"]["kind"] != "group" {
                let flavor = match (field["cardinality"].as_str().unwrap(), field["required"] == true) {
                    ("one", true) => "exactly-one",
                    ("one", false) => "optional",
                    _ => "many",
                };
                cardinalities.insert(flavor);
            }
        }
    }
    assert_eq!(
        modes,
        ["compile", "item", "policy", "rules"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    );
    assert!(
        kinds.contains("css")
            && kinds.contains("xpath")
            && kinds.contains("item-css")
            && kinds.contains("item-xpath")
    );
    assert_eq!(
        cardinalities,
        BTreeSet::from(["exactly-one", "many", "optional"]),
        "item cardinality classes"
    );
    for axis in [
        "ancestor",
        "ancestor-or-self",
        "attribute",
        "child",
        "descendant",
        "descendant-or-self",
        "following",
        "following-sibling",
        "namespace",
        "parent",
        "preceding",
        "preceding-sibling",
        "self",
    ] {
        assert!(
            xpath
                .iter()
                .any(|e| e.match_indices(&format!("{axis}::")).any(|(at, _)| {
                    e[..at]
                        .chars()
                        .next_back()
                        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'))
                })),
            "no rule uses the {axis} axis"
        );
    }
    for function in [
        "boolean",
        "ceiling",
        "concat",
        "contains",
        "count",
        "false",
        "floor",
        "id",
        "lang",
        "last",
        "local-name",
        "name",
        "namespace-uri",
        "normalize-space",
        "not",
        "number",
        "position",
        "round",
        "starts-with",
        "string",
        "string-length",
        "substring",
        "substring-after",
        "substring-before",
        "sum",
        "translate",
        "true",
    ] {
        assert!(has_call(&xpath, function), "no rule calls {function}()");
    }
    assert_eq!(
        transforms.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "builtin",
            "clean",
            "dedupe",
            "iso_date",
            "join",
            "json_parse",
            "limit",
            "normalize_whitespace",
            "number",
            "regex",
            "resolve_url",
            "trim"
        ],
        "item transforms"
    );
}

/// Each one-over fixture sits exactly on its policy constant: the accepted rule is at the limit
/// and the failing rule is one unit beyond it.
#[test]
fn limit_fixtures_sit_exactly_on_the_policy_constants() {
    let case = |id: &str| selector_cases().into_iter().find(|c| c.entry.id == id).unwrap();
    let rules = |id: &str| -> BTreeMap<String, Value> {
        case(id).entry.params["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| (rule["id"].as_str().unwrap().to_owned(), rule.clone()))
            .collect()
    };

    let bytes = rules("s38-limit-expression-bytes");
    assert_eq!(rule_expression(&bytes["x_ok"]).len(), MAX_EXPRESSION_BYTES);
    assert_eq!(rule_expression(&bytes["x_over"]).len(), MAX_EXPRESSION_BYTES + 1);
    assert_eq!(rule_expression(&bytes["c_ok"]).len(), MAX_EXPRESSION_BYTES);
    assert_eq!(rule_expression(&bytes["c_over"]).len(), MAX_EXPRESSION_BYTES + 1);

    // Syntax nodes: every string argument, the two function calls; a path counts itself and each step.
    let nodes = rules("s39-limit-ast-nodes");
    let arguments = |rule: &Value| rule_expression(rule).matches("'a'").count();
    assert_eq!(arguments(&nodes["f_ok"]) + 2, MAX_AST_NODES);
    assert_eq!(arguments(&nodes["f_over"]) + 2, MAX_AST_NODES + 1);
    let steps = |rule: &Value| rule_expression(rule).split('/').count();
    assert_eq!(steps(&nodes["s_ok"]) + 1, MAX_AST_NODES);
    assert_eq!(steps(&nodes["s_over"]) + 1, MAX_AST_NODES + 1);

    // Left-associative chains and unions stop at depth 64; nesting stops at 63 levels.
    let depth = rules("s40-limit-ast-depth-and-unions");
    assert_eq!(rule_expression(&depth["u_ok"]).matches("//p").count(), 64);
    assert_eq!(rule_expression(&depth["u_over"]).matches("//p").count(), 65);
    assert_eq!(rule_expression(&depth["a_ok"]).matches('1').count(), 64);
    assert_eq!(rule_expression(&depth["a_over"]).matches('1').count(), 65);
    let parser = rules("s41-limit-parser-depth");
    assert_eq!(rule_expression(&parser["p_ok"]).matches('(').count(), 63);
    assert_eq!(rule_expression(&parser["p_over"]).matches('(').count(), 64);
    assert_eq!(rule_expression(&parser["m_ok"]).matches('-').count(), 63);
    assert_eq!(rule_expression(&parser["m_over"]).matches('-').count(), 64);

    // Selected nodes: the page holds one paragraph more than the node-set ceiling.
    let selected = case("s42-limit-selected-nodes");
    assert_eq!(selected.html.matches("<p>").count(), MAX_SELECTED + 1);
    let selected_rules = rules("s42-limit-selected-nodes");
    assert!(rule_expression(&selected_rules["r1"]).contains(&format!("<= {MAX_SELECTED}")));

    // The operation budget is a shared ceiling of one million units.
    assert_eq!(MAX_OPERATIONS, 1_000_000);
    assert_eq!(MAX_EXPRESSION_BYTES, 4096);
    assert_eq!(MAX_AST_NODES, 512);
    assert_eq!(MAX_SELECTED, 10_000);
}

// ------------------------------------------------------------------------------------------
// feed family
// ------------------------------------------------------------------------------------------

fn feed_cases() -> Vec<Case> {
    cases_of(&["feed"])
}

fn feed_error(error: &FeedError) -> String {
    match error {
        FeedError::Policy(DiscoveryErrorV1::Protocol(reason)) => format!("Policy::Protocol({reason})"),
        FeedError::Policy(DiscoveryErrorV1::Limit(what)) => format!("Policy::Limit({what})"),
        FeedError::Xml(_) => "Xml".to_owned(),
        FeedError::Json(_) => "Json".to_owned(),
        other => format!("{other:?}"),
    }
}

fn sitemap_error(error: &UrlError) -> String {
    match error {
        UrlError::Sitemap(reason) => format!("Sitemap({reason})"),
        other => format!("{other:?}"),
    }
}

/// Everything one feed case produced, for the gold comparison and the cross checks.
struct FeedRun {
    lines: Vec<Line>,
    /// Every URL the parsers proposed, before scope.
    raw: BTreeSet<String>,
    requests: Vec<String>,
    denied_requests: usize,
    truncated: bool,
    kind: Option<String>,
    entries: Option<usize>,
    /// Entries of the first document when it is parsed with the default budget.
    total: Option<usize>,
    skipped_for_depth: Option<usize>,
}

struct Admission {
    filter: ScopeFilter,
    raw: BTreeSet<String>,
    lines: Vec<Line>,
    seen: BTreeSet<Line>,
    requests: Vec<String>,
    denied_requests: usize,
}

impl Admission {
    /// Scope decides every proposal; an admitted proposal is recorded once per provenance.
    fn propose(&mut self, label: &str, url: &Url) -> bool {
        self.raw.insert(url.as_str().to_owned());
        if self.filter.decide(url) != ScopeDecision::InScope {
            return false;
        }
        let line = (label.to_owned(), url.as_str().to_owned());
        if self.seen.insert(line.clone()) {
            self.lines.push(line);
        }
        true
    }

    /// The caller requests a further document. A request to a denied origin is a violation.
    fn request(&mut self, url: &Url) {
        if self.filter.decide(url) != ScopeDecision::InScope {
            self.denied_requests += 1;
        }
        self.requests.push(url.as_str().to_owned());
        self.lines.push(("request".to_owned(), url.as_str().to_owned()));
    }
}

fn document_bytes(case: &Case, params: &Value, probe: &Probe) -> Vec<u8> {
    let text = probe.apply(&case.html);
    match params.get("encoding").and_then(Value::as_str) {
        Some("base64") => base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .unwrap(),
        _ => text.into_bytes(),
    }
}

fn file_url(text: &str) -> Url {
    Url::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn fetch<'a>(documents: &'a BTreeMap<String, String>, url: &Url, id: &str) -> &'a str {
    documents
        .get(url.as_str())
        .unwrap_or_else(|| panic!("{id}: no fixture document for requested {url}"))
}

fn sitemap_page_lines(
    adm: &mut Admission,
    urls: &[crawlx_url::sitemap::SitemapUrl],
    policy: &SourceDiscoveryPolicyV1,
) {
    for entry in urls {
        if policy
            .sitemap_lastmod
            .as_ref()
            .is_some_and(|window| !window.includes(entry.lastmod.as_ref()))
        {
            continue;
        }
        adm.propose("page", &file_url(&entry.loc));
        for variant in &entry.hreflang {
            adm.propose("variant", &file_url(&variant.loc));
        }
    }
}

fn run_feed(case: &Case, probe: &Probe) -> FeedRun {
    let params = probe.params(case);
    let id = &case.entry.id;
    let bytes = document_bytes(case, &params, probe);
    let policy: SourceDiscoveryPolicyV1 =
        serde_json::from_value(params.get("policy").cloned().unwrap_or_else(|| json!({}))).unwrap();
    policy.validate().unwrap();
    let scope: Scope = serde_json::from_value(params["scope"].clone()).unwrap();
    let seed = file_url(params["seed"].as_str().unwrap());
    let base = file_url(&case.entry.page_url);
    let documents: BTreeMap<String, String> = params
        .get("documents")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let mut adm = Admission {
        filter: ScopeFilter::new(&seed, &scope).unwrap(),
        raw: BTreeSet::new(),
        lines: Vec::new(),
        seen: BTreeSet::new(),
        requests: Vec::new(),
        denied_requests: 0,
    };
    let mut run = FeedRun {
        lines: Vec::new(),
        raw: BTreeSet::new(),
        requests: Vec::new(),
        denied_requests: 0,
        truncated: false,
        kind: None,
        entries: None,
        total: None,
        skipped_for_depth: None,
    };
    match params["format"].as_str().unwrap() {
        "feed" => {
            let follow = params.get("follow").and_then(Value::as_bool).unwrap_or(false);
            let mut queue = VecDeque::from([(base.clone(), bytes.clone())]);
            let mut visited = BTreeSet::from([base.as_str().to_owned()]);
            let mut first = true;
            while let Some((location, body)) = queue.pop_front() {
                if !first {
                    adm.request(&location);
                }
                let document = match parse_feed(&body, &location, &policy) {
                    Ok(document) => document,
                    Err(error) => {
                        assert!(first, "{id}: a followed page failed to parse: {error:?}");
                        adm.lines.push(("error".to_owned(), feed_error(&error)));
                        break;
                    }
                };
                if first {
                    run.truncated = document.truncated;
                    run.kind = Some(format!("{:?}", document.kind));
                    run.total = Some(
                        parse_feed(&body, &location, &SourceDiscoveryPolicyV1::default())
                            .unwrap()
                            .entries
                            .len(),
                    );
                    if params.get("streamParity").and_then(Value::as_bool) == Some(true) {
                        assert_stream_parity(id, &body, &location, &policy, &document);
                    }
                }
                let entry_label = if matches!(document.kind, FeedKind::Atom) {
                    "alternate"
                } else {
                    "item"
                };
                for entry in &document.entries {
                    adm.propose(entry_label, &entry.url);
                    for media in &entry.media {
                        adm.propose("media", media);
                    }
                    for more in &entry.read_more {
                        adm.propose("read_more", more);
                    }
                }
                for next in &document.next {
                    if adm.propose("next", next) && follow && visited.insert(next.as_str().to_owned()) {
                        queue.push_back((next.clone(), fetch(&documents, next, id).as_bytes().to_vec()));
                    }
                }
                first = false;
            }
        }
        "sitemap" => match SitemapParser::parse_limited(&bytes, policy.max_entries) {
            Ok(document) => {
                run.truncated = document.truncated;
                run.entries = Some(document.urls.len());
                run.total = Some(SitemapParser::parse(&bytes).unwrap().urls.len());
                assert!(!document.gzip && !document.malformed, "{id}");
                sitemap_page_lines(&mut adm, &document.urls, &policy);
            }
            Err(error) => adm.lines.push(("error".to_owned(), sitemap_error(&error))),
        },
        "sitemap-gzip" => {
            let document = SitemapParser::parse(&bytes).unwrap();
            assert!(
                document.gzip && document.kind == SitemapKind::Gzip && document.urls.is_empty(),
                "{id}"
            );
            assert!(
                bytes.starts_with(&[0x1f, 0x8b]),
                "{id}: fixture is real gzip data"
            );
            adm.lines
                .push(("transport".to_owned(), "gzip-detected".to_owned()));
            match SitemapTraversal::new().ingest_root(base.as_str(), &bytes) {
                Err(error) => adm.lines.push(("error".to_owned(), sitemap_error(&error))),
                Ok(pending) => panic!("{id}: gzip sitemap was ingested: {pending:?}"),
            }
        }
        "sitemap-traversal" => {
            let mut traversal = SitemapTraversal::new();
            let mut known = 0;
            let mut queue: VecDeque<PendingSitemap> = VecDeque::new();
            match traversal.ingest_root(base.as_str(), &bytes) {
                Ok(pending) => queue.extend(pending),
                Err(error) => adm.lines.push(("error".to_owned(), sitemap_error(&error))),
            }
            sitemap_page_lines(&mut adm, traversal.urls(), &policy);
            known = known.max(traversal.urls().len());
            while let Some(nested) = queue.pop_front() {
                let location = file_url(&nested.loc);
                adm.raw.insert(location.as_str().to_owned());
                if adm.filter.decide(&location) != ScopeDecision::InScope {
                    continue;
                }
                adm.request(&location);
                let more = traversal
                    .ingest(fetch(&documents, &location, id).as_bytes(), nested.depth)
                    .unwrap();
                let fresh = traversal.urls()[known..].to_vec();
                sitemap_page_lines(&mut adm, &fresh, &policy);
                known = traversal.urls().len();
                queue.extend(more);
            }
            run.truncated = traversal.truncated();
            run.skipped_for_depth = Some(traversal.skipped_for_depth());
        }
        other => panic!("{id}: unknown format {other}"),
    }
    if policy.url_language_hint.is_some() {
        // The hint only orders: matching evidence first, none next, conflicting last.
        assert!(
            adm.lines
                .iter()
                .all(|(label, _)| matches!(label.as_str(), "item" | "page" | "variant")),
            "{id}"
        );
        adm.lines
            .sort_by_key(|(_, url)| Reverse(policy.language_rank(&file_url(url))));
    }
    run.lines = adm.lines;
    run.raw = adm.raw;
    run.requests = adm.requests;
    run.denied_requests = adm.denied_requests;
    run
}

/// The streaming adapter projects the same article rows as the whole-document parser.
fn assert_stream_parity(
    id: &str,
    body: &[u8],
    location: &Url,
    policy: &SourceDiscoveryPolicyV1,
    document: &crawlx_url::feed::FeedDocument,
) {
    let mut stream = XmlFeedStream::new(body.to_vec(), location.clone(), policy.clone()).unwrap();
    let mut urls: Vec<Url> = Vec::new();
    for row in stream.by_ref() {
        for entry in row.unwrap().document.unwrap().entries {
            if !urls.contains(&entry.url) {
                urls.push(entry.url);
            }
        }
    }
    let expected: Vec<&Url> = document.entries.iter().map(|e| &e.url).collect();
    assert_eq!(
        urls.iter().collect::<Vec<_>>(),
        expected,
        "{id}: stream rows differ from the parsed entries"
    );
    assert_eq!(
        stream.next_links(),
        document.next,
        "{id}: stream pagination differs"
    );
}

#[test]
fn feed_gold_is_one_span_per_line() {
    for case in feed_cases() {
        assert_gold_shape(&case);
        assert!(
            Url::parse(&case.entry.page_url)
                .unwrap()
                .host_str()
                .unwrap()
                .ends_with(".test"),
            "{}",
            case.entry.id
        );
    }
}

#[test]
fn feeds_admit_exactly_the_gold_url_set_and_make_no_denied_or_real_request() {
    let probe = Probe::new();
    for case in feed_cases() {
        let params = probe.params(&case);
        let id = &case.entry.id;
        let run = run_feed(&case, &probe);
        assert_eq!(run.lines, gold_lines(&case, &probe), "{id}");
        // Two runs agree: the result is a pure function of the document and the policy.
        assert_eq!(
            run_feed(&case, &probe).lines,
            run.lines,
            "{id}: not deterministic"
        );

        let expect = &params["expect"];
        assert_eq!(
            run.truncated,
            expect["truncated"].as_bool().unwrap(),
            "{id}: truncation"
        );
        if let Some(kind) = expect.get("kind").and_then(Value::as_str) {
            assert_eq!(run.kind.as_deref(), Some(kind), "{id}: feed format");
        }
        if let Some(entries) = expect.get("entries").and_then(Value::as_u64) {
            assert_eq!(
                run.entries,
                Some(as_usize(entries)),
                "{id}: parsed sitemap entries"
            );
        }
        if let Some(skipped) = expect.get("skippedForDepth").and_then(Value::as_u64) {
            assert_eq!(
                run.skipped_for_depth,
                Some(as_usize(skipped)),
                "{id}: depth-skipped sitemaps"
            );
        }

        // The entry budget is exact: a document is truncated exactly when it holds more
        // entries than the budget, and only that many entries are proposed.
        if let (Some(budget), Some(total)) = (params["policy"]["maxEntries"].as_u64(), run.total) {
            let budget = as_usize(budget);
            assert_eq!(
                run.truncated,
                total > budget,
                "{id}: {total} entries against a budget of {budget}"
            );
        }

        // Denied origins were proposed by the document but are neither admitted nor requested.
        let admitted: BTreeSet<&str> = run.lines.iter().map(|(_, url)| url.as_str()).collect();
        for denied in strings(params.get("denied")) {
            assert!(
                run.raw.contains(&denied),
                "{id}: {denied} was never proposed by the document"
            );
            assert!(!admitted.contains(denied.as_str()), "{id}: {denied} was admitted");
            assert!(!run.requests.contains(&denied), "{id}: {denied} was requested");
        }
        for never in strings(params.get("neverProposed")) {
            assert!(!run.raw.contains(&never), "{id}: {never} must not be proposed");
        }
        assert_eq!(run.denied_requests, 0, "{id}: request to a denied origin");
        for request in &run.requests {
            let seed = file_url(params["seed"].as_str().unwrap());
            let scope: Scope = serde_json::from_value(params["scope"].clone()).unwrap();
            assert_eq!(
                ScopeFilter::new(&seed, &scope)
                    .unwrap()
                    .decide(&file_url(request)),
                ScopeDecision::InScope,
                "{id}: {request}"
            );
        }
    }
    probe.assert_untouched("feed family");
}

fn element_depth(markup: &str) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    for tag in markup.split('<').skip(1) {
        let tag = tag.split('>').next().unwrap();
        if tag.starts_with('/') {
            depth -= 1;
        } else if !(tag.starts_with('?') || tag.starts_with('!') || tag.ends_with('/')) {
            depth += 1;
            deepest = deepest.max(depth);
        }
    }
    deepest
}

#[test]
fn feed_family_covers_formats_provenance_budgets_and_transport() {
    let probe = Probe::new();
    let cases = feed_cases();
    assert!(cases.len() >= 24, "{} feed cases, plan minimum 24", cases.len());
    let ids: BTreeSet<&str> = cases.iter().map(|c| c.entry.id.as_str()).collect();
    assert_eq!(ids.len(), cases.len());
    assert!(ids.iter().all(|id| id.starts_with('d')));

    let runs: Vec<(String, Value, FeedRun)> = cases
        .iter()
        .map(|case| (case.entry.id.clone(), probe.params(case), run_feed(case, &probe)))
        .collect();

    // Every feed format and every sitemap variant is present.
    let kinds: BTreeSet<&str> = runs
        .iter()
        .filter_map(|(_, _, run)| run.kind.as_deref())
        .collect();
    assert_eq!(kinds, BTreeSet::from(["Atom", "Json", "Rdf", "Rss"]));
    let formats: BTreeSet<&str> = runs
        .iter()
        .map(|(_, p, _)| p["format"].as_str().unwrap())
        .collect();
    assert_eq!(
        formats,
        BTreeSet::from(["feed", "sitemap", "sitemap-gzip", "sitemap-traversal"])
    );
    let labels: BTreeSet<&str> = runs
        .iter()
        .flat_map(|(_, _, run)| run.lines.iter().map(|(label, _)| label.as_str()))
        .collect();
    for label in [
        "alternate",
        "error",
        "item",
        "media",
        "next",
        "page",
        "read_more",
        "request",
        "transport",
        "variant",
    ] {
        assert!(labels.contains(label), "no case yields a {label} line");
    }
    let sitemap_text = cases.iter().any(|c| c.entry.files.input.path.ends_with(".txt"));
    assert!(sitemap_text, "plain-text sitemap");
    assert!(
        runs.iter()
            .any(|(_, p, r)| p["format"] == "sitemap-traversal" && r.requests.len() >= 4),
        "nested sitemap traversal"
    );
    assert!(
        runs.iter()
            .any(|(_, p, r)| p["follow"] == true && r.requests.len() >= 2),
        "feed pagination loop"
    );
    // Cross-origin: several cases propose denied origins and request none.
    let with_denied = runs.iter().filter(|(_, p, _)| p.get("denied").is_some()).count();
    assert!(with_denied >= 10, "{with_denied} cases with denied origins");
    assert!(runs.iter().all(|(_, _, r)| r.denied_requests == 0));

    // One-over entry budgets: a document holding exactly the budget is complete, one more entry
    // truncates it; shown for RSS, Atom, JSON Feed and sitemaps.
    let budgets: Vec<(&str, bool)> = runs
        .iter()
        .filter_map(|(_, p, r)| {
            let budget = as_usize(p["policy"]["maxEntries"].as_u64()?);
            let family = r.kind.as_deref().unwrap_or("Sitemap");
            Some((family, r.total? > budget))
        })
        .collect();
    for family in ["Atom", "Json", "Rss", "Sitemap"] {
        assert!(budgets.contains(&(family, true)), "{family}: no over-budget case");
    }
    for family in ["Json", "Rss", "Sitemap"] {
        assert!(
            budgets.contains(&(family, false)),
            "{family}: no exact-budget case"
        );
    }
    // Byte budget: exactly the document length is accepted, one byte less is a typed limit error.
    let by_id = |id: &str| cases.iter().position(|c| c.entry.id == id).unwrap();
    let exact = by_id("d21-budget-bytes-exact");
    let over = by_id("d22-budget-bytes-over");
    let length = cases[exact].html.len();
    assert_eq!(runs[exact].1["policy"]["maxFeedBytes"], length);
    assert_eq!(runs[over].1["policy"]["maxFeedBytes"], length - 1);
    // Nesting: the fixtures sit on the default nesting limit of 32 elements.
    let limit = SourceDiscoveryPolicyV1::default().max_nesting;
    assert_eq!(limit, 32);
    assert_eq!(element_depth(&cases[by_id("d23-nesting-exact")].html), limit);
    assert_eq!(element_depth(&cases[by_id("d24-nesting-over")].html), limit + 1);
    // Sitemap nesting sits on the traversal depth limit.
    assert_eq!(MAX_DEPTH, 5);
    let deepest = |id: &str| runs[by_id(id)].1["documents"].as_object().unwrap().len();
    assert_eq!(deepest("d51-sitemap-depth-exact"), MAX_DEPTH);
    assert_eq!(deepest("d52-sitemap-depth-over"), MAX_DEPTH + 1);
    // Gzip transport: both compressed fixtures are real gzip data that the pure parsers do not
    // decode, and each has a decoded twin with the same URLs.
    for (compressed, decoded) in [
        ("d30-transport-gzip-feed", "d31-transport-decoded-feed"),
        ("d45-transport-gzip-sitemap", "d46-transport-decoded-sitemap"),
    ] {
        let params = &runs[by_id(compressed)].1;
        assert_eq!(params["encoding"], "base64");
        let bytes = document_bytes(&cases[by_id(compressed)], params, &probe);
        assert!(bytes.starts_with(&[0x1f, 0x8b, 0x08]), "{compressed}");
        assert!(!runs[by_id(decoded)].2.lines.is_empty());
    }
    probe.assert_untouched("feed coverage");
}
