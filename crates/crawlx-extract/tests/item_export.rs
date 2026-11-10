//! Exporter corpus: exact bytes for Unicode, nested and missing-field items, with explicit CSV
//! formula and XML scalar/CDATA policies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::item_export::{
    write_item_with, CsvFormulaPolicy, ItemExportOptions, XmlControlPolicy, XmlTextMode,
};
use crawlx_extract::serialize::{write_item, ArticleWriteError, ItemFormat};
use serde_json::{json, Map, Value};

/// Same members as `corpus()` inserted in the opposite order.
fn corpus_reversed() -> Value {
    let mut map = Map::new();
    map.insert("num".into(), json!(-12));
    map.insert("nul".into(), Value::Null);
    map.insert("mid".into(), json!("=HYPERLINK(\"x\")"));
    map.insert("empty".into(), json!(""));
    map.insert(
        "alpha".into(),
        json!({"nested": [1, 2.5, null, true], "k\"ey": "v"}),
    );
    map.insert("zeta".into(), json!("Ünïcödé ✓ 日本語 🎉"));
    Value::Object(map)
}

fn corpus() -> Value {
    json!({
        "zeta": "Ünïcödé ✓ 日本語 🎉",
        "alpha": {"nested": [1, 2.5, null, true], "k\"ey": "v"},
        "mid": "=HYPERLINK(\"x\")",
        "empty": "",
        "nul": null,
        "num": -12
    })
}

fn render(item: &Value, format: ItemFormat, options: &ItemExportOptions) -> String {
    let mut out = Vec::new();
    write_item_with(&mut out, item, format, options).unwrap();
    String::from_utf8(out).unwrap()
}

const JSON_BYTES: &str = "{\"alpha\":{\"k\\\"ey\":\"v\",\"nested\":[1,2.5,null,true]},\"empty\":\"\",\"mid\":\"=HYPERLINK(\\\"x\\\")\",\"nul\":null,\"num\":-12,\"zeta\":\"Ünïcödé ✓ 日本語 🎉\"}\n";

const CSV_BYTES: &str = "\"alpha\",\"empty\",\"mid\",\"nul\",\"num\",\"zeta\"\n\"{\"\"k\\\"\"ey\"\":\"\"v\"\",\"\"nested\"\":[1,2.5,null,true]}\",\"\",\"'=HYPERLINK(\"\"x\"\")\",\"null\",\"-12\",\"Ünïcödé ✓ 日本語 🎉\"\n";

const XML_BYTES: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<item version=\"1\"><object><field name=\"alpha\"><object><field name=\"k&quot;ey\"><string>v</string></field><field name=\"nested\"><array><entry><number>1</number></entry><entry><number>2.5</number></entry><entry><null/></entry><entry><boolean>true</boolean></entry></array></field></object></field><field name=\"empty\"><string></string></field><field name=\"mid\"><string>=HYPERLINK(&quot;x&quot;)</string></field><field name=\"nul\"><null/></field><field name=\"num\"><number>-12</number></field><field name=\"zeta\"><string>Ünïcödé ✓ 日本語 🎉</string></field></object></item>\n";

#[test]
fn corpus_bytes_are_pinned_for_every_format_regardless_of_insertion_order() {
    let defaults = ItemExportOptions::default();
    for item in [corpus(), corpus_reversed()] {
        assert_eq!(render(&item, ItemFormat::Json, &defaults), JSON_BYTES);
        assert_eq!(render(&item, ItemFormat::Jsonl, &defaults), JSON_BYTES);
        assert_eq!(render(&item, ItemFormat::Csv, &defaults), CSV_BYTES);
        assert_eq!(render(&item, ItemFormat::Xml, &defaults), XML_BYTES);
    }
}

#[test]
fn plain_write_item_matches_default_options() {
    for format in [
        ItemFormat::Json,
        ItemFormat::Jsonl,
        ItemFormat::Csv,
        ItemFormat::Xml,
    ] {
        let mut plain = Vec::new();
        write_item(&mut plain, &corpus(), format).unwrap();
        assert_eq!(
            String::from_utf8(plain).unwrap(),
            render(&corpus(), format, &ItemExportOptions::default())
        );
    }
}

#[test]
fn csv_explicit_columns_pin_order_and_distinguish_missing_empty_and_null() {
    let mut options = ItemExportOptions::default();
    options.csv_columns = Some(vec!["zeta".into(), "absent".into(), "empty".into(), "nul".into()]);
    assert_eq!(
        render(&corpus(), ItemFormat::Csv, &options),
        "\"zeta\",\"absent\",\"empty\",\"nul\"\n\"Ünïcödé ✓ 日本語 🎉\",,\"\",\"null\"\n"
    );
    // Rows appended under an existing header carry no header line.
    options.csv_header = false;
    assert_eq!(
        render(&corpus(), ItemFormat::Csv, &options),
        "\"Ünïcödé ✓ 日本語 🎉\",,\"\",\"null\"\n"
    );
    // Another item with a different key set lines up under the same columns.
    let other = json!({"empty": "x", "zeta": "z", "extra": "dropped"});
    assert_eq!(render(&other, ItemFormat::Csv, &options), "\"z\",,\"x\",\n");

    options.csv_columns = Some(vec!["a".into(), "a".into()]);
    assert!(write_item_with(&mut Vec::new(), &corpus(), ItemFormat::Csv, &options).is_err());
    options.csv_columns = Some(Vec::new());
    assert!(write_item_with(&mut Vec::new(), &corpus(), ItemFormat::Csv, &options).is_err());
}

#[test]
fn csv_formula_policy_is_explicit() {
    let item =
        json!({"a": "=1+1", "b": "+SUM(A1)", "c": "-2", "d": "@cmd", "e": "\t=x", "f": "ok", "g": "  =lead"});
    let prefixed = render(&item, ItemFormat::Csv, &ItemExportOptions::default());
    assert_eq!(
        prefixed,
        "\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\"\n\"'=1+1\",\"'+SUM(A1)\",\"'-2\",\"'@cmd\",\"'\t=x\",\"ok\",\"'  =lead\"\n"
    );

    let mut reject = ItemExportOptions::default();
    reject.csv_formula = CsvFormulaPolicy::Reject;
    let mut out = Vec::new();
    let error = write_item_with(&mut out, &item, ItemFormat::Csv, &reject).unwrap_err();
    assert!(matches!(error, ArticleWriteError::CsvFormula));
    assert!(out.is_empty(), "rejection precedes every record byte");

    // Header cells are checked too; a clean item passes unchanged.
    let hostile_key = json!({"=x": "fine"});
    assert!(matches!(
        write_item_with(&mut Vec::new(), &hostile_key, ItemFormat::Csv, &reject),
        Err(ArticleWriteError::CsvFormula)
    ));
    reject.csv_header = false;
    assert_eq!(render(&hostile_key, ItemFormat::Csv, &reject), "\"fine\"\n");
    let clean = json!({"a": "plain", "b": 5});
    let mut rejecting = ItemExportOptions::default();
    rejecting.csv_formula = CsvFormulaPolicy::Reject;
    assert_eq!(
        render(&clean, ItemFormat::Csv, &ItemExportOptions::default()),
        render(&clean, ItemFormat::Csv, &rejecting)
    );
    // Only emitted columns are checked: a dangerous field outside the projection is not exported.
    let mut projected = ItemExportOptions::default();
    projected.csv_formula = CsvFormulaPolicy::Reject;
    projected.csv_columns = Some(vec!["f".into()]);
    assert_eq!(render(&item, ItemFormat::Csv, &projected), "\"f\"\n\"ok\"\n");
}

#[test]
fn xml_scalar_policy_rejects_or_replaces_forbidden_characters() {
    let item = json!({"k\u{2}": "a\u{1}b\u{fffe}c\u{7f}d"});
    let mut out = Vec::new();
    let error = write_item_with(&mut out, &item, ItemFormat::Xml, &ItemExportOptions::default()).unwrap_err();
    assert!(matches!(error, ArticleWriteError::InvalidXmlScalar));
    assert!(out.is_empty());

    let mut replace = ItemExportOptions::default();
    replace.xml_control = XmlControlPolicy::Replace;
    let escaped = render(&item, ItemFormat::Xml, &replace);
    // U+007F is a legal (discouraged) XML 1.0 character and is kept.
    assert!(
        escaped.contains("<field name=\"k\u{fffd}\"><string>a\u{fffd}b\u{fffd}c\u{7f}d</string></field>"),
        "{escaped}"
    );

    replace.xml_text = XmlTextMode::Cdata;
    let cdata = render(&item, ItemFormat::Xml, &replace);
    assert!(
        cdata.contains(
            "<field name=\"k\u{fffd}\"><string><![CDATA[a\u{fffd}b\u{fffd}c\u{7f}d]]></string></field>"
        ),
        "{cdata}"
    );

    // JSON keeps the original scalar either way.
    assert_eq!(
        render(&item, ItemFormat::Jsonl, &ItemExportOptions::default()),
        "{\"k\\u0002\":\"a\\u0001b\u{fffe}c\u{7f}d\"}\n"
    );
}

#[test]
fn xml_cdata_mode_splits_terminators_and_keeps_carriage_returns_escaped() {
    let item = json!({"s": "a]]>b<&\"'", "cr": "x\ry", "e": "", "tab": "t\tn\n", "u": "日本🎉"});
    let mut options = ItemExportOptions::default();
    options.xml_text = XmlTextMode::Cdata;
    let xml = render(&item, ItemFormat::Xml, &options);
    assert_eq!(
        xml,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<item version=\"1\"><object>\
<field name=\"cr\"><string>x&#13;y</string></field>\
<field name=\"e\"><string><![CDATA[]]></string></field>\
<field name=\"s\"><string><![CDATA[a]]]]><![CDATA[>b<&\"']]></string></field>\
<field name=\"tab\"><string><![CDATA[t\tn\n]]></string></field>\
<field name=\"u\"><string><![CDATA[日本🎉]]></string></field>\
</object></item>\n"
    );
    // Field names stay escaped even in CDATA mode.
    let keyed = json!({"a<b>\"": "v"});
    assert!(render(&keyed, ItemFormat::Xml, &options).contains("<field name=\"a&lt;b&gt;&quot;\">"));
}
