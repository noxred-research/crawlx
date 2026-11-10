//! Declarative storefront recipe: one item per variant, decimal-string prices, source ids,
//! pagination as an explicit intent over separately supplied local bodies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::extraction::DiscoveryPurposeV1;
use crawlx_extract::recipe::{
    FieldKindV1, NextPageV1, RecipeError, RecipeFault, RecipeFieldV1, StorefrontRecipeV1,
};
use serde_json::{json, Value};
use url::Url;

fn url(text: &str) -> Url {
    Url::parse(text).unwrap()
}

/// The built-in layout with a two-product page size so a small fixture paginates.
fn small_pages() -> StorefrontRecipeV1 {
    let mut recipe = StorefrontRecipeV1::collection_products();
    recipe.next_page = Some(NextPageV1::Param {
        param: "page".into(),
        per_page: 2,
    });
    recipe
}

fn page_one() -> Value {
    json!({"products": [
        {"id": 101, "handle": "mug", "title": "Mug", "vendor": "Acme", "product_type": "Cup", "variants": [
            {"id": 9001, "sku": "MUG-R", "title": "Red", "price": "12.50", "compare_at_price": "15.00", "available": true},
            {"id": 9002, "sku": "MUG-B", "title": "Blue", "price": "12.50", "compare_at_price": null, "available": false}
        ]},
        {"id": "p-102", "handle": "jar", "title": "Jar", "variants": [
            {"id": 9003, "sku": null, "title": "Default Title", "price": "0.05"}
        ]}
    ]})
}

fn page_two() -> Value {
    json!({"products": [
        {"id": "p-102", "handle": "jar", "title": "Jar", "variants": [
            {"id": 9003, "sku": null, "title": "Default Title", "price": "0.05"}
        ]},
        {"id": 103, "handle": "lid", "title": "Lid", "variants": [
            {"id": 9004, "title": "Small", "price": 4.5},
            {"id": 9005, "title": "Large", "price": "4,50"},
            {"id": 9006, "title": "No price"},
            "not-an-object",
            {"id": 9007, "title": "Big", "price": "6", "available": true}
        ]},
        {"id": 104, "handle": "bare", "title": "Bare"},
        42
    ]})
}

#[test]
fn emits_one_item_per_variant_with_decimal_string_prices_and_source_ids() {
    let recipe = small_pages().compile().unwrap();
    let page = recipe
        .extract_page(
            &url("https://store.example.test/collections/mugs/products.json?limit=2"),
            &page_one(),
        )
        .unwrap();
    assert!(page.rejected.is_empty());
    assert_eq!(
        page.items,
        vec![
            json!({"product_id": "101", "handle": "mug", "title": "Mug", "vendor": "Acme", "product_type": "Cup",
                   "variant_id": "9001", "sku": "MUG-R", "variant_title": "Red", "price": "12.50",
                   "compare_at_price": "15.00", "available": true}),
            json!({"product_id": "101", "handle": "mug", "title": "Mug", "vendor": "Acme", "product_type": "Cup",
                   "variant_id": "9002", "sku": "MUG-B", "variant_title": "Blue", "price": "12.50",
                   "compare_at_price": null, "available": false}),
            json!({"product_id": "p-102", "handle": "jar", "title": "Jar", "vendor": null, "product_type": null,
                   "variant_id": "9003", "sku": null, "variant_title": "Default Title", "price": "0.05",
                   "compare_at_price": null, "available": null}),
        ]
    );
    for item in &page.items {
        assert!(item["price"].is_string(), "prices are strings, never numbers");
    }
    // Two products fill the page, so the next page is announced as an intent, not fetched.
    let next = page.next.unwrap();
    assert_eq!(
        next.url.as_str(),
        "https://store.example.test/collections/mugs/products.json?limit=2&page=2"
    );
    assert_eq!(next.purpose, DiscoveryPurposeV1::ReadMoreReference);
}

#[test]
fn pages_merge_in_order_and_faults_are_typed_per_variant() {
    let recipe = small_pages().compile().unwrap();
    let first = url("https://store.example.test/c/products.json?limit=2&page=1");
    let second = url("https://store.example.test/c/products.json?limit=2&page=2");
    let output = recipe
        .extract_pages(&[(first, page_one()), (second, page_two())])
        .unwrap();
    assert_eq!(output.pages, 2);
    // Page two repeats variant 9003 (overlap) and adds one valid variant.
    assert_eq!(output.duplicates, 1);
    let ids: Vec<&str> = output
        .items
        .iter()
        .map(|item| item["variant_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["9001", "9002", "9003", "9007"]);
    assert_eq!(output.items[3]["price"], json!("6"));

    let faults: Vec<_> = output
        .rejected
        .iter()
        .map(|(page, rejection)| {
            (
                *page,
                rejection.product,
                rejection.variant,
                rejection.fault.clone(),
            )
        })
        .collect();
    assert_eq!(
        faults,
        vec![
            (1, 1, Some(0), RecipeFault::FloatNumber("price".into())),
            (1, 1, Some(1), RecipeFault::InvalidDecimal("price".into())),
            (1, 1, Some(2), RecipeFault::MissingField("price".into())),
            (1, 1, Some(3), RecipeFault::VariantNotObject),
            (1, 2, None, RecipeFault::VariantsMissing),
            (1, 3, None, RecipeFault::ProductNotObject),
        ]
    );
    // Four entries fill a two-product page, so page three is announced.
    assert_eq!(
        output.next.unwrap().url.as_str(),
        "https://store.example.test/c/products.json?limit=2&page=3"
    );
}

#[test]
fn last_page_announces_nothing_and_a_missing_array_is_an_error() {
    let recipe = small_pages().compile().unwrap();
    let short = json!({"products": [page_one()["products"][0].clone()]});
    let page = recipe
        .extract_page(&url("https://store.example.test/p.json?page=7"), &short)
        .unwrap();
    assert!(page.next.is_none());
    assert_eq!(page.items.len(), 2);
    assert_eq!(
        recipe
            .extract_page(&url("https://store.example.test/p.json"), &json!({"items": []}))
            .unwrap_err(),
        RecipeError::ProductsNotArray
    );
}

#[test]
fn explicit_next_field_resolves_relative_and_refuses_other_origins() {
    let mut recipe = small_pages();
    recipe.next_page = Some(NextPageV1::Field {
        path: "links.next".into(),
    });
    let recipe = recipe.compile().unwrap();
    let base = url("https://store.example.test/c/products.json?page=1");
    let body = |next: Value| {
        let mut body = page_one();
        body["links"] = json!({ "next": next });
        body
    };
    let next = recipe
        .extract_page(&base, &body(json!("/c/products.json?page=2#frag")))
        .unwrap()
        .next
        .unwrap();
    assert_eq!(
        next.url.as_str(),
        "https://store.example.test/c/products.json?page=2"
    );
    for refused in [
        json!("https://evil.example.test/c/products.json?page=2"),
        json!("http://store.example.test/c/products.json?page=2"),
        json!("https://user:pw@store.example.test/next"),
        json!("javascript:alert(1)"),
        json!("https://store.example.test/c/products.json?page=1"),
        json!(""),
        json!(7),
        Value::Null,
    ] {
        assert!(
            recipe
                .extract_page(&base, &body(refused.clone()))
                .unwrap()
                .next
                .is_none(),
            "{refused}"
        );
    }
    assert!(recipe.extract_page(&base, &page_one()).unwrap().next.is_none());
}

#[test]
fn minor_units_use_integer_arithmetic_and_floats_are_refused() {
    let recipe: StorefrontRecipeV1 = serde_json::from_value(json!({
        "version": 1,
        "products": "data.items",
        "variants": "offers",
        "productFields": [{"name": "id", "path": "ref", "kind": {"kind": "id"}, "required": true}],
        "variantFields": [
            {"name": "amount", "path": "price.amount", "kind": {"kind": "minor_units", "exponent": 2}},
            {"name": "sku", "path": "codes[1]", "kind": {"kind": "text"}}
        ]
    }))
    .unwrap();
    let recipe = recipe.compile().unwrap();
    let body = json!({"data": {"items": [{"ref": "a", "offers": [
        {"price": {"amount": 1999}, "codes": ["x", "SKU-1"]},
        {"price": {"amount": 5}},
        {"price": {"amount": -250}},
        {"price": {"amount": 0}},
        {"price": {"amount": 19.99}},
        {"price": {"amount": "1999"}},
        {"price": {"amount": 18446744073709551615u64}}
    ]}]}});
    let page = recipe
        .extract_page(&url("https://s.example.test/x"), &body)
        .unwrap();
    let amounts: Vec<_> = page.items.iter().map(|item| item["amount"].clone()).collect();
    assert_eq!(
        amounts,
        [json!("19.99"), json!("0.05"), json!("-2.50"), json!("0.00")]
    );
    assert_eq!(page.items[0]["sku"], json!("SKU-1"));
    assert_eq!(page.items[1]["sku"], Value::Null);
    let faults: Vec<_> = page
        .rejected
        .iter()
        .map(|rejection| rejection.fault.clone())
        .collect();
    assert_eq!(
        faults,
        vec![
            RecipeFault::FloatNumber("amount".into()),
            RecipeFault::InvalidValue("amount".into()),
            RecipeFault::InvalidValue("amount".into()),
        ]
    );
    assert!(page.next.is_none());
}

#[test]
fn recipe_is_digest_pinned_and_validated() {
    let recipe = StorefrontRecipeV1::collection_products();
    let compiled = recipe.compile().unwrap();
    let digest = compiled.digest();
    // The digest survives a serde round trip and pins the exact recipe.
    let round_trip: StorefrontRecipeV1 =
        serde_json::from_value(serde_json::to_value(&recipe).unwrap()).unwrap();
    assert_eq!(round_trip, recipe);
    assert_eq!(round_trip.compile_pinned(&digest).unwrap().digest(), digest);
    let mut changed = recipe.clone();
    changed
        .variant_fields
        .push(RecipeFieldV1::new("barcode", "barcode", FieldKindV1::Text));
    assert_eq!(
        changed.compile_pinned(&digest).unwrap_err(),
        RecipeError::DigestMismatch
    );
    assert_ne!(changed.compile().unwrap().digest(), digest);

    let invalid = |edit: &dyn Fn(&mut StorefrontRecipeV1)| {
        let mut recipe = StorefrontRecipeV1::collection_products();
        edit(&mut recipe);
        recipe.compile().unwrap_err()
    };
    assert!(matches!(invalid(&|r| r.version = 2), RecipeError::Invalid(_)));
    assert!(matches!(
        invalid(&|r| r.products = "a..b".into()),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r.products = "a[".into()),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r.products = "a[x]".into()),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r.products = ".a".into()),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r.products = "a.".into()),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r.products = "a.b.c.d.e.f.g.h.i".into()),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r
            .variant_fields
            .push(RecipeFieldV1::new("price", "x", FieldKindV1::Text))),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r.variant_fields.push(RecipeFieldV1::new(
            "p",
            "x",
            FieldKindV1::MinorUnits { exponent: 19 }
        ))),
        RecipeError::Invalid(_)
    ));
    assert!(matches!(
        invalid(&|r| r.next_page = Some(NextPageV1::Param {
            param: "page".into(),
            per_page: 0
        })),
        RecipeError::Invalid(_)
    ));
    // Unknown members are refused when a recipe is read from JSON.
    assert!(serde_json::from_value::<StorefrontRecipeV1>(json!({
        "version": 1, "products": "p", "variants": "v", "productFields": [], "variantFields": [], "eval": "1+1"
    }))
    .is_err());
    // Root-level array bodies and indexed paths are expressible.
    let root: StorefrontRecipeV1 = serde_json::from_value(json!({
        "version": 1, "products": "", "variants": "[0].list",
        "productFields": [{"name": "t", "path": "title", "kind": {"kind": "text"}}],
        "variantFields": [{"name": "n", "path": "n", "kind": {"kind": "decimal"}}]
    }))
    .unwrap();
    let page = root
        .compile()
        .unwrap()
        .extract_page(&url("https://s.example.test/"), &json!([{"title": "T"}]))
        .unwrap();
    assert_eq!(page.rejected.len(), 1);
    assert_eq!(page.rejected[0].fault, RecipeFault::VariantsMissing);
}
