//! Authored no-LLM item recipe semantics: CSS pseudo-elements, nested groups, sibling sources,
//! defaults, attribute/list projections and the typed transforms. No network, no fixtures on disk.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::selectors::{FieldQualityV1, ItemLoaderV1, ItemOutcomeV1};
use crawlx_extract::{
    handlers::{AttributesHandler, TextHandler, TextHandlers},
    item_loader::{project_outcome, CompiledItemLoader},
    xpath::{CompiledSelector, SelectorDocument, SelectorError, XPathValue},
};
use scraper::Html;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use url::Url;

fn recipe(value: Value) -> ItemLoaderV1 {
    serde_json::from_value(value).unwrap()
}
fn base() -> Url {
    Url::parse("https://fixture.test/dir/").unwrap()
}
fn load(spec: &ItemLoaderV1, source: &str) -> ItemOutcomeV1 {
    let html = Html::parse_document(source);
    let mut doc = SelectorDocument::new(&html).unwrap();
    CompiledItemLoader::compile(spec)
        .unwrap()
        .load(&mut doc, &base())
        .unwrap()
}
fn css(expression: &str) -> Value {
    json!({"kind":"css","expression":expression})
}
fn xpath(expression: &str) -> Value {
    json!({"kind":"xpath","expression":expression})
}

const MENU: &str = "<h1>Title</h1><ul class='menu'><li><a href='/a' data-x='1'>Alpha</a></li>\
    <li><a href='b'>Beta</a></li></ul>";

#[test]
fn css_text_and_attr_pseudo_elements_yield_exact_typed_fields() {
    let spec = recipe(json!({"version":1,"fields":[
        {"name":"labels","selectors":[css("ul.menu a::text")],"extraction":{"kind":"text"},"cardinality":"many"},
        {"name":"links","selectors":[css("ul.menu a::attr(href)")],"extraction":{"kind":"text"},
            "cardinality":"many","transforms":[{"kind":"resolve_url"}]},
        {"name":"first_x","selectors":[css("a::attr(data-x)")],"extraction":{"kind":"text"},"cardinality":"one"},
        {"name":"quoted","selectors":[css("a::attr('data-x')")],"extraction":{"kind":"text"},"cardinality":"one"},
        {"name":"union","selectors":[css("h1::text, ul.menu li:first-child a::text")],
            "extraction":{"kind":"text"},"cardinality":"many"},
        {"name":"xpath_text","selectors":[xpath("//ul/li/a/text()")],"extraction":{"kind":"text"},"cardinality":"many"},
        {"name":"xpath_attr","selectors":[xpath("//ul/li/a/@href")],"extraction":{"kind":"text"},"cardinality":"many"},
        {"name":"whole","selectors":[css("::text")],"extraction":{"kind":"text"},"cardinality":"many"}
    ]}));
    let outcome = load(&spec, MENU);
    assert!(outcome.valid);
    assert_eq!(outcome.item["labels"], json!(["Alpha", "Beta"]));
    assert_eq!(
        outcome.item["links"],
        json!(["https://fixture.test/a", "https://fixture.test/dir/b"])
    );
    assert_eq!(outcome.item["first_x"], "1");
    assert_eq!(outcome.item["quoted"], "1");
    assert_eq!(outcome.item["union"], json!(["Title", "Alpha"]));
    assert_eq!(outcome.item["xpath_text"], json!(["Alpha", "Beta"]));
    assert_eq!(outcome.item["xpath_attr"], json!(["/a", "b"]));
    assert_eq!(outcome.item["whole"], json!(["Title", "Alpha", "Beta"]));
}

#[test]
fn unsupported_pseudo_elements_are_typed_errors_not_empty_matches() {
    for expression in [
        "a::before",
        "a::first-line",
        "a::text b",
        "a::attr(href) b",
        "p::selection",
        "a, b::after",
    ] {
        let spec = recipe(json!({"version":1,"fields":[
            {"name":"x","selectors":[css(expression)],"extraction":{"kind":"text"},"cardinality":"many"}]}));
        assert!(
            matches!(
                CompiledItemLoader::compile(&spec),
                Err(SelectorError::Unsupported(_))
            ),
            "{expression}"
        );
    }
    // Invalid attribute names and plain syntax errors keep their own variants.
    for expression in ["a::attr()", "a::attr(bad name)", "a[", ""] {
        let spec = recipe(json!({"version":1,"fields":[
            {"name":"x","selectors":[css(expression)],"extraction":{"kind":"text"},"cardinality":"many"}]}));
        let error = CompiledItemLoader::compile(&spec);
        assert!(
            matches!(error, Err(SelectorError::Syntax) | Err(SelectorError::Policy(_))),
            "{expression}: {error:?}"
        );
    }
}

#[test]
fn pseudo_elements_cannot_prune_or_include_elements() {
    let html = Html::parse_document(MENU);
    let mut doc = SelectorDocument::new(&html).unwrap();
    let policy: crawlx_core::selectors::SelectorPolicyV1 =
        serde_json::from_value(json!({"include":[css("a::text")]})).unwrap();
    assert!(matches!(
        doc.select_policy(&policy),
        Err(SelectorError::NodeSetRequired)
    ));
    let compiled = CompiledSelector::compile(&serde_json::from_value(css("a::text")).unwrap()).unwrap();
    assert!(matches!(
        doc.evaluate(&compiled, &BTreeMap::new()).unwrap(),
        XPathValue::Nodes(nodes) if nodes.len() == 2
    ));
}

#[test]
fn schema_has_no_fetch_or_eval_surface() {
    let spec = recipe(json!({"version":1,"fields":[
        {"name":"x","selectors":[xpath("document('https://fixture.test/x')")],"extraction":{"kind":"text"},"cardinality":"one"}]}));
    assert!(matches!(
        CompiledItemLoader::compile(&spec),
        Err(SelectorError::UnsupportedFunction)
    ));
}

const SHOP: &str = "<div class='shop'>\
    <div class='product' id='p1'><h2>Widget</h2><span class='price'>$5</span>\
      <ul class='tags'><li>a</li><li>b</li></ul><a class='buy' href='/buy/1'>Buy</a></div>\
    <div class='product' id='p2'><h2>Gadget</h2><ul class='tags'></ul><a class='buy'>x</a></div>\
    <dl><dt>Color</dt><dd>red</dd><dt>Size</dt><dd>L</dd></dl></div>";

fn shop_spec() -> ItemLoaderV1 {
    recipe(json!({"version":1,"fields":[
        {"name":"products","selectors":[css(".product")],"extraction":{"kind":"group"},"cardinality":"many","fields":[
            {"name":"name","selectors":[css("h2")],"extraction":{"kind":"text"},"cardinality":"one","required":true},
            {"name":"price","selectors":[css(".price")],"extraction":{"kind":"text"},"cardinality":"one","default":"n/a"},
            {"name":"tags","selectors":[css("ul.tags li")],"extraction":{"kind":"text"},"cardinality":"many"},
            {"name":"href","selectors":[css("a.buy")],"extraction":{"kind":"attribute","name":"href"},
                "cardinality":"one","transforms":[{"kind":"resolve_url"}]},
            {"name":"id","selectors":[xpath(".")],"extraction":{"kind":"attribute","name":"id"},"cardinality":"one"}
        ]},
        {"name":"specs","selectors":[css("dt")],"extraction":{"kind":"group"},"cardinality":"many","fields":[
            {"name":"label","selectors":[xpath(".")],"extraction":{"kind":"text"},"cardinality":"one"},
            {"name":"value","selectors":[xpath(".")],"extraction":{"kind":"text"},"cardinality":"one",
                "source":{"kind":"next_sibling"}}
        ]},
        {"name":"terms","selectors":[css("dd")],"extraction":{"kind":"group"},"cardinality":"many","fields":[
            {"name":"term","selectors":[xpath(".")],"extraction":{"kind":"text"},"cardinality":"one",
                "source":{"kind":"previous_sibling","selector":css("dt")}}
        ]},
        {"name":"missing_group","selectors":[css(".nothing")],"extraction":{"kind":"group"},"cardinality":"many","fields":[
            {"name":"n","selectors":[xpath(".")],"extraction":{"kind":"text"},"cardinality":"one"}]}
    ]}))
}

#[test]
fn nested_groups_sibling_sources_and_defaults_produce_exact_typed_json() {
    let outcome = load(&shop_spec(), SHOP);
    assert!(outcome.valid);
    assert_eq!(
        outcome.item,
        json!({
            "products":[
                {"name":"Widget","price":"$5","tags":["a","b"],"href":"https://fixture.test/buy/1","id":"p1"},
                {"name":"Gadget","price":"n/a","tags":[],"id":"p2"}
            ],
            "specs":[{"label":"Color","value":"red"},{"label":"Size","value":"L"}],
            "terms":[{"term":"Color"},{"term":"Size"}],
            "missing_group":[]
        })
    );
    // Defaults stay labeled per instance.
    let products = &outcome.fields[0];
    assert_eq!(products.quality, FieldQualityV1::Selected);
    assert_eq!(products.groups.len(), 2);
    let quality = |instance: usize, name: &str| {
        products.groups[instance]
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .quality
    };
    assert_eq!(quality(0, "price"), FieldQualityV1::Selected);
    assert_eq!(quality(1, "price"), FieldQualityV1::Defaulted);
    assert_eq!(quality(1, "href"), FieldQualityV1::Missing);
    assert_eq!(quality(1, "tags"), FieldQualityV1::Missing);
    assert_eq!(outcome.fields[3].quality, FieldQualityV1::Missing);
    assert!(outcome.fields[3].groups.is_empty());
}

#[test]
fn nested_required_child_failure_invalidates_the_item_and_loading_is_deterministic() {
    let source = "<div class='product'><span class='price'>1</span></div>";
    let outcome = load(&shop_spec(), source);
    assert!(!outcome.valid);
    let child = &outcome.fields[0].groups[0][0];
    assert_eq!(child.name, "name");
    assert_eq!(child.quality, FieldQualityV1::Missing);
    assert_eq!(outcome.fields[0].value, Some(json!([{"price":"1","tags":[]}])));
    let again = load(&shop_spec(), source);
    assert_eq!(outcome, again);
}

#[test]
fn group_admission_rules_are_enforced() {
    let bad = |field: Value| {
        let spec: Result<ItemLoaderV1, _> = serde_json::from_value(json!({"version":1,"fields":[field]}));
        CompiledItemLoader::compile(&spec.unwrap()).is_err()
    };
    let leaf = json!({"name":"n","selectors":[xpath(".")],"extraction":{"kind":"text"},"cardinality":"one"});
    // group without children, children without group, transforms on groups,
    // sibling source at top level.
    assert!(bad(
        json!({"name":"g","selectors":[css("div")],"extraction":{"kind":"group"},"cardinality":"many"})
    ));
    assert!(bad(
        json!({"name":"g","selectors":[css("div")],"extraction":{"kind":"text"},"cardinality":"many","fields":[leaf.clone()]})
    ));
    assert!(bad(
        json!({"name":"g","selectors":[css("div")],"extraction":{"kind":"group"},"cardinality":"many",
        "transforms":[{"kind":"trim"}],"fields":[leaf.clone()]})
    ));
    assert!(bad(
        json!({"name":"g","selectors":[css("div")],"extraction":{"kind":"text"},"cardinality":"one",
        "source":{"kind":"next_sibling"}})
    ));
    // Nesting deeper than four levels.
    let mut deep = leaf.clone();
    for level in 0..4 {
        deep = json!({"name":format!("g{level}"),"selectors":[css("div")],"extraction":{"kind":"group"},
            "cardinality":"many","fields":[deep]});
    }
    assert!(bad(deep));
    // Three levels are fine.
    let mut ok = leaf;
    for level in 0..2 {
        ok = json!({"name":format!("g{level}"),"selectors":[css("div")],"extraction":{"kind":"group"},
            "cardinality":"many","fields":[ok]});
    }
    assert!(!bad(ok));
}

const CARD: &str = "<div id='card' data-info='{\"a\":1,\"b\":[2,3]}' data-id='42' class='c1 c2'>\
    <p> Call   me: +1 415-555-0132 or mail ops@example.com </p>\
    <ul><li>x1</li><li>y22</li><li>z333</li></ul></div>";

fn card_spec() -> ItemLoaderV1 {
    recipe(json!({"version":1,"fields":[
        {"name":"attrs","selectors":[css("#card")],"extraction":{"kind":"attributes"},"cardinality":"one"},
        {"name":"info","selectors":[css("#card::attr(data-info)")],"extraction":{"kind":"text"},
            "cardinality":"one","transforms":[{"kind":"json_parse"}]},
        {"name":"cleaned","selectors":[css("p::text")],"extraction":{"kind":"text"},"cardinality":"one",
            "transforms":[{"kind":"clean"}]},
        {"name":"email","selectors":[css("p")],"extraction":{"kind":"text"},"cardinality":"one",
            "transforms":[{"kind":"builtin","name":"email"}]},
        {"name":"nums","selectors":[css("li::text")],"extraction":{"kind":"text"},"cardinality":"many",
            "transforms":[{"kind":"regex","pattern":"\\d+"},{"kind":"limit","count":2}]},
        {"name":"all_digits","selectors":[css("li::text")],"extraction":{"kind":"text"},"cardinality":"many",
            "transforms":[{"kind":"regex","pattern":"([a-z])(\\d+)","group":2,"all":true}]},
        {"name":"missing_match","selectors":[css("p")],"extraction":{"kind":"text"},"cardinality":"one",
            "transforms":[{"kind":"regex","pattern":"zzz+"}]},
        {"name":"bad_json","selectors":[css("p")],"extraction":{"kind":"text"},"cardinality":"one",
            "transforms":[{"kind":"json_parse"}]}
    ]}))
}

#[test]
fn typed_transforms_match_the_handler_api_and_failures_are_labeled() {
    let outcome = load(&card_spec(), CARD);
    assert_eq!(
        outcome.item["attrs"],
        json!({"class":"c1 c2","data-id":"42","data-info":"{\"a\":1,\"b\":[2,3]}","id":"card"})
    );
    assert_eq!(outcome.item["info"], json!({"a":1,"b":[2,3]}));
    assert_eq!(
        outcome.item["cleaned"],
        "Call me: +1 415-555-0132 or mail ops@example.com"
    );
    assert_eq!(outcome.item["email"], "ops@example.com");
    assert_eq!(outcome.item["nums"], json!(["1", "22"]));
    assert_eq!(outcome.item["all_digits"], json!(["1", "22", "333"]));
    let quality = |name: &str| outcome.fields.iter().find(|f| f.name == name).unwrap().quality;
    assert_eq!(quality("missing_match"), FieldQualityV1::MalformedTransform);
    assert_eq!(quality("bad_json"), FieldQualityV1::MalformedTransform);
    assert!(!outcome.valid);

    // The handler API produces the same values for the same extracted strings.
    let paragraph = TextHandler::new(" Call   me: +1 415-555-0132 or mail ops@example.com ");
    assert_eq!(
        Value::String(paragraph.clean().into_string()),
        outcome.item["cleaned"]
    );
    assert_eq!(
        Value::String(
            paragraph
                .builtin("email")
                .unwrap()
                .first()
                .unwrap()
                .as_str()
                .to_owned()
        ),
        outcome.item["email"]
    );
    let items = TextHandlers::from_strings(["x1", "y22", "z333"].map(String::from)).unwrap();
    assert_eq!(
        items.regex(r"\d+", 0).unwrap().limit(2).to_value(),
        outcome.item["nums"]
    );
    assert_eq!(
        items.regex(r"([a-z])(\d+)", 2).unwrap().to_value(),
        outcome.item["all_digits"]
    );
    assert_eq!(
        TextHandler::new(r#"{"a":1,"b":[2,3]}"#).json().unwrap(),
        outcome.item["info"]
    );
    let html = Html::parse_document(CARD);
    let card = html
        .select(&scraper::Selector::parse("#card").unwrap())
        .next()
        .unwrap();
    assert_eq!(
        AttributesHandler::from_element(card).to_value(),
        outcome.item["attrs"]
    );
}

#[test]
fn regex_transforms_are_admitted_at_compile_time() {
    for (transform, check) in [
        (json!({"kind":"regex","pattern":"(a)\\1"}), "backreference"),
        (json!({"kind":"regex","pattern":"a(?=b)"}), "lookaround"),
        (json!({"kind":"regex","pattern":"(a)","group":4}), "group"),
        (json!({"kind":"builtin","name":"no_such_pattern"}), "unknown"),
    ] {
        let spec = recipe(json!({"version":1,"fields":[
            {"name":"x","selectors":[css("p")],"extraction":{"kind":"text"},"cardinality":"one","transforms":[transform]}]}));
        assert!(
            matches!(CompiledItemLoader::compile(&spec), Err(SelectorError::Regex(_))),
            "{check}"
        );
    }
}

#[test]
fn privacy_projection_recurses_into_group_outcomes() {
    let spec = shop_spec();
    let mut outcome = load(&spec, SHOP);
    project_outcome(&mut outcome, &spec, &|s| Some(s.to_owned())).unwrap();
    assert!(outcome.valid);
    assert_eq!(outcome.fields[0].groups.len(), 2);

    let mut outcome = load(&spec, SHOP);
    project_outcome(&mut outcome, &spec, &|s| {
        Some(if s == "Widget" {
            "W".to_owned()
        } else {
            s.to_owned()
        })
    })
    .unwrap();
    assert_eq!(outcome.item["products"][0]["name"], "W");
    assert_eq!(outcome.fields[0].groups[0][0].value, Some(json!("W")));
    assert!(outcome.fields[0].redacted);

    // A removed nested value removes the whole group field and its per-instance outcomes.
    let mut outcome = load(&spec, SHOP);
    project_outcome(&mut outcome, &spec, &|s| (s != "Gadget").then(|| s.to_owned())).unwrap();
    assert!(!outcome.valid);
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::Redacted);
    assert!(outcome.fields[0].groups.is_empty());
    assert!(outcome.item.get("products").is_none());
    assert_eq!(outcome.item["specs"][0]["label"], "Color");
}

#[test]
fn attributes_and_json_fields_pass_final_type_checks() {
    let spec = card_spec();
    let mut outcome = load(&spec, CARD);
    project_outcome(&mut outcome, &spec, &|s| Some(s.to_owned())).unwrap();
    let quality = |name: &str| outcome.fields.iter().find(|f| f.name == name).unwrap().quality;
    assert_eq!(quality("attrs"), FieldQualityV1::Selected);
    assert_eq!(quality("info"), FieldQualityV1::Selected);
    assert_eq!(outcome.item["info"], json!({"a":1,"b":[2,3]}));
}

#[test]
fn legacy_recipes_and_outcomes_serialize_without_the_new_fields() {
    let spec = recipe(json!({"version":1,"fields":[
        {"name":"t","selectors":[css("h1")],"extraction":{"kind":"text"},"cardinality":"one"}]}));
    let encoded = serde_json::to_string(&spec).unwrap();
    assert!(
        !encoded.contains("\"fields\":[]") && !encoded.contains("source"),
        "{encoded}"
    );
    let outcome = load(&spec, "<h1>x</h1>");
    let encoded = serde_json::to_string(&outcome).unwrap();
    assert!(!encoded.contains("groups"), "{encoded}");
    assert_eq!(outcome.item, json!({"t":"x"}));
}
