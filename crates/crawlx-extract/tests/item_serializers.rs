//! Generic item formats are real wire encodings, separate from article TEI.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_extract::serialize::{write_item, ItemFormat};
use serde_json::{json, Value};

#[test]
fn generic_csv_quotes_nested_json_and_protects_spreadsheet_cells() {
    let item = json!({"z":"  =SUM(A1)","a":{"quote":"a\"b"},"middle":[true,7]});
    let mut output = Vec::new();
    write_item(&mut output, &item, ItemFormat::Csv).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.starts_with("\"a\",\"middle\",\"z\"\n"));
    assert!(output.contains("\"{\"\"quote\"\":\"\"a\\\"\"b\"\"}\""));
    assert!(output.contains("\"[true,7]\""));
    assert!(output.contains("\"'  =SUM(A1)\""));
    assert!(!output.starts_with('{'), "CSV cannot be relabelled JSON bytes");
}

#[test]
fn generic_xml_escapes_keys_and_values_and_preserves_typed_nested_structure() {
    let item = json!({"not<a>tag":"line\t\n\r<&\"", "values":[true,7,null]});
    let mut output = Vec::new();
    write_item(&mut output, &item, ItemFormat::Xml).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(output.contains("name=\"not&lt;a&gt;tag\""));
    assert!(output.contains("line&#9;&#10;&#13;&lt;&amp;&quot;"));
    assert!(output.contains("<array><entry><boolean>true</boolean></entry><entry><number>7</number></entry><entry><null/></entry></array>"));
    assert!(!output.contains("<!DOCTYPE"));
}

#[test]
fn depth_and_node_bounds_apply_to_every_item_format_before_output() {
    let mut nested = Value::Null;
    for _ in 0..40 {
        nested = Value::Array(vec![nested]);
    }
    let nested = json!({"nested":nested});
    for format in [
        ItemFormat::Json,
        ItemFormat::Jsonl,
        ItemFormat::Csv,
        ItemFormat::Xml,
    ] {
        let mut output = Vec::new();
        assert!(write_item(&mut output, &nested, format).is_err());
        assert!(
            output.is_empty(),
            "structural rejection must precede record bytes"
        );
    }
    let wide = json!({"values":vec![Value::Null;100_001]});
    let mut output = Vec::new();
    assert!(write_item(&mut output, &wide, ItemFormat::Json).is_err());
    assert!(output.is_empty());
}

#[test]
fn xml_forbidden_scalars_fail_before_header_while_json_preserves_the_value() {
    let item = json!({"value":"before\u{1}after"});
    let mut output = Vec::new();
    assert!(write_item(&mut output, &item, ItemFormat::Xml).is_err());
    assert!(output.is_empty());
    write_item(&mut output, &item, ItemFormat::Jsonl).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), item);
    assert_eq!(output.last(), Some(&b'\n'));
}

#[test]
fn string_and_output_byte_bounds_are_enforced_without_an_unbounded_output_sink() {
    let item = json!({"value":"x".repeat(16*1024*1024+1)});
    let mut output = Vec::new();
    assert!(write_item(&mut output, &item, ItemFormat::Json).is_err());
    assert!(output.is_empty());
    let escaped = json!({"value":"\"".repeat(8*1024*1024+1)});
    let mut count = CountingSink(0);
    assert!(write_item(&mut count, &escaped, ItemFormat::Json).is_err());
    assert!(count.0 <= 16 * 1024 * 1024);
}
struct CountingSink(usize);
impl std::io::Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
