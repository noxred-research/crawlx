//! Struct-tag manifest translation: an exported collector struct becomes a versioned item recipe
//! that yields the expected item; every Go type the recipe cannot express exactly is reported and
//! blocks the recipe, never zero-filled.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::item_loader::{
    translate_struct_tags, CompiledItemLoader, StructTagManifestV1, StructTagTranslation,
};
use crawlx_extract::xpath::SelectorDocument;
use scraper::Html;
use serde_json::{json, Value};
use url::Url;

fn manifest(fields: Value) -> StructTagManifestV1 {
    serde_json::from_value(json!({ "version": 1, "fields": fields })).unwrap()
}

fn translate(fields: Value) -> StructTagTranslation {
    translate_struct_tags(&manifest(fields))
}

const PAGE: &str = "<html><body><h1> Title </h1><a class='more' href='/next'>More</a>\
    <ul><li class='tag'>a</li><li class='tag'>b</li></ul>\
    <div class='author'><span class='name'>Ann</span><a href='/ann'>profile</a></div>\
    <div class='author'><span class='name'>Bob</span><a href='/bob'>profile</a></div>\
    <p id='only'><b>Solo</b></p></body></html>";

fn load(loader: &crawlx_core::selectors::ItemLoaderV1) -> Value {
    let html = Html::parse_document(PAGE);
    let mut doc = SelectorDocument::new(&html).unwrap();
    let outcome = CompiledItemLoader::compile(loader)
        .unwrap()
        .load(&mut doc, &Url::parse("https://fixture.test/").unwrap())
        .unwrap();
    outcome.item
}

#[test]
fn an_exported_struct_yields_the_expected_item() {
    let t = translate(json!([
        {"name": "Title", "goType": "string", "selector": "h1"},
        {"name": "Next", "goType": "*string", "selector": "a.more", "attr": "href"},
        {"name": "Tags", "goType": "[]string", "selector": "li.tag"},
        {"name": "Links", "goType": "[]*string", "selector": ".author a", "attr": "href"},
        {"name": "Authors", "goType": "[]struct", "selector": ".author", "fields": [
            {"name": "Name", "goType": "string", "selector": ".name"},
            {"name": "Profile", "goType": "string", "selector": "a", "attr": "href"}
        ]},
        {"name": "Solo", "goType": "*struct", "selector": "#only", "fields": [
            {"name": "Bold", "goType": "string", "selector": "b"}
        ]}
    ]));
    assert!(t.complete(), "{:?}", t.rows);
    assert!(t.rows.iter().all(|row| row.translated && !row.reason.is_empty()));
    let paths: Vec<&str> = t.rows.iter().map(|row| row.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "Title",
            "Next",
            "Tags",
            "Links",
            "Authors",
            "Authors.Name",
            "Authors.Profile",
            "Solo",
            "Solo.Bold"
        ]
    );
    let loader = t.loader.unwrap();
    // the recipe is the versioned native one
    assert_eq!(loader.version, 1);
    assert_eq!(loader.fields.len(), 6);
    let item = load(&loader);
    assert_eq!(item["Title"].as_str().map(str::trim), Some("Title"));
    assert_eq!(item["Next"], "/next");
    assert_eq!(item["Tags"], json!(["a", "b"]));
    assert_eq!(item["Links"], json!(["/ann", "/bob"]));
    assert_eq!(
        item["Authors"],
        json!([{"Name": "Ann", "Profile": "/ann"}, {"Name": "Bob", "Profile": "/bob"}])
    );
    assert_eq!(item["Solo"]["Bold"], "Solo");
}

#[test]
fn every_unsupported_go_type_is_reported_and_blocks_the_recipe() {
    for go_type in [
        "map[string]string",
        "[]map[string]string",
        "chan string",
        "<-chan string",
        "func(string) string",
        "interface{}",
        "any",
        "[3]string",
        "int",
        "int64",
        "uint8",
        "float64",
        "bool",
        "[]int",
        "*bool",
        "time.Time",
        "Author",
        "[]Author",
        "",
    ] {
        let t = translate(json!([
            {"name": "Title", "goType": "string", "selector": "h1"},
            {"name": "Odd", "goType": go_type, "selector": "p"}
        ]));
        assert!(!t.complete(), "{go_type:?} must not produce a recipe");
        assert!(t.loader.is_none());
        let odd = t.rows.iter().find(|row| row.path == "Odd").unwrap();
        assert!(!odd.translated, "{go_type:?}");
        assert!(!odd.reason.is_empty());
        // the supported field is still reported as translatable, the caller gets the complete list
        assert!(t.rows.iter().find(|row| row.path == "Title").unwrap().translated);
    }
}

#[test]
fn reasons_name_the_kind_of_type_that_was_refused() {
    let reason = |go_type: &str| {
        translate(json!([{"name": "F", "goType": go_type, "selector": "p"}])).rows[0]
            .reason
            .to_owned()
    };
    assert!(reason("map[string]int").contains("map"));
    assert!(reason("chan int").contains("channel"));
    assert!(reason("func()").contains("function"));
    assert!(reason("interface{}").contains("interface"));
    assert!(reason("[2]string").contains("array"));
    assert!(reason("int").contains("numeric"));
    assert!(reason("Foo").contains("named or unknown"));
}

#[test]
fn an_untagged_field_is_not_silently_dropped() {
    let t = translate(json!([
        {"name": "Title", "goType": "string", "selector": "h1"},
        {"name": "Untagged", "goType": "string"}
    ]));
    assert!(!t.complete());
    let row = t.rows.iter().find(|row| row.path == "Untagged").unwrap();
    assert!(!row.translated);
    assert!(row.reason.contains("zero value"), "{}", row.reason);
}

#[test]
fn structural_mistakes_are_rows_not_panics() {
    for (fields, needle) in [
        // a struct with nothing tagged inside
        (
            json!([{"name": "S", "goType": "struct", "selector": "div"}]),
            "nothing to extract",
        ),
        // nested fields on a scalar
        (
            json!([{"name": "S", "goType": "string", "selector": "div", "fields": [
                {"name": "X", "goType": "string", "selector": "b"}]}]),
            "only valid on a struct",
        ),
        // an attribute tag on a struct selects no value
        (
            json!([{"name": "S", "goType": "struct", "selector": "div", "attr": "id", "fields": [
                {"name": "X", "goType": "string", "selector": "b"}]}]),
            "attribute tag on a struct",
        ),
        // an empty attribute or selector
        (
            json!([{"name": "S", "goType": "string", "selector": "div", "attr": ""}]),
            "attribute tag is empty",
        ),
        (
            json!([{"name": "S", "goType": "string", "selector": "  "}]),
            "selector tag is empty",
        ),
        // an unsupported field nested in a struct blocks the struct
        (
            json!([{"name": "S", "goType": "[]struct", "selector": "div", "fields": [
                {"name": "M", "goType": "map[string]string", "selector": "b"}]}]),
            "nested field is unsupported",
        ),
    ] {
        let t = translate(fields.clone());
        assert!(!t.complete(), "{fields}");
        assert!(
            t.rows
                .iter()
                .any(|row| !row.translated && row.reason.contains(needle)),
            "{fields}: {:?}",
            t.rows
        );
    }
}

#[test]
fn recipe_bounds_are_reported_and_the_manifest_schema_is_strict() {
    // a duplicate key cannot be a recipe: the native loader refuses it, and every row says so
    let t = translate(json!([
        {"name": "A", "goType": "string", "selector": "h1"},
        {"name": "A", "goType": "string", "selector": "p"}
    ]));
    assert!(!t.complete());
    assert!(t
        .rows
        .iter()
        .all(|row| !row.translated && row.reason.contains("bounds")));
    // too many fields at one level
    let many: Vec<Value> = (0..65)
        .map(|n| json!({"name": format!("F{n}"), "goType": "string", "selector": "p"}))
        .collect();
    assert!(!translate(Value::Array(many)).complete());
    assert!(!translate(json!([])).complete());
    // nesting deeper than the recipe allows
    let mut deep = json!({"name": "Leaf", "goType": "string", "selector": "b"});
    for level in 0..6 {
        deep = json!({"name": format!("S{level}"), "goType": "struct", "selector": "div", "fields": [deep]});
    }
    assert!(!translate(json!([deep])).complete());
    // an unknown version and unknown manifest fields never reach the translator
    let stale: StructTagManifestV1 = serde_json::from_value(json!({"version": 2, "fields": []})).unwrap();
    assert!(!translate_struct_tags(&stale).complete());
    assert!(
        serde_json::from_value::<StructTagManifestV1>(json!({"version": 1, "fields": [], "extra": 1}))
            .is_err()
    );
    assert!(serde_json::from_value::<StructTagManifestV1>(
        json!({"version": 1, "fields": [{"name": "A", "goType": "string", "selector": "p", "tag": "x"}]})
    )
    .is_err());
}

#[test]
fn a_translated_recipe_round_trips_as_a_native_recipe_document() {
    let t = translate(json!([
        {"name": "Tags", "goType": "[]string", "selector": "li.tag"},
        {"name": "Next", "goType": "string", "selector": "a.more", "attr": "href"}
    ]));
    let loader = t.loader.unwrap();
    let wire = serde_json::to_value(&loader).unwrap();
    assert_eq!(wire["version"], 1);
    assert_eq!(wire["fields"][0]["cardinality"], "many");
    assert_eq!(
        wire["fields"][0]["selectors"][0],
        json!({"kind": "css", "expression": "li.tag"})
    );
    assert_eq!(
        wire["fields"][1]["extraction"],
        json!({"kind": "attribute", "name": "href"})
    );
    let again: crawlx_core::selectors::ItemLoaderV1 = serde_json::from_value(wire).unwrap();
    assert_eq!(again, loader);
}
