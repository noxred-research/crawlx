//! Authored MIT streaming export fixtures; no upstream content or runtime network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::{
    serialize::{write_article, ArticleFormat, ArticleStream},
    Document, ExtractOptions, Extractor,
};
use url::Url;

fn document() -> Document {
    let mut document = Extractor::extract(
        "<main><p>The council reopened the bridge after inspecting all structural supports.</p></main>",
        &Url::parse("https://fixture.invalid/").unwrap(),
        &ExtractOptions::default(),
    )
    .unwrap();
    document.text = "\tline\r\n中文🙂 <&> \"quoted\"".to_owned();
    document.comments = "=SUM(1,2)".to_owned();
    document.title = Some(" \t@formula".to_owned());
    document
}

#[test]
fn xml_preserves_scalars_and_attribute_whitespace_and_rejects_forbidden_controls() {
    let mut document = document();
    let mut bytes = Vec::new();
    let mut stream = ArticleStream::begin(&mut bytes, ArticleFormat::Xml).unwrap();
    stream.push("file\t\r\n<&>\".html", &document).unwrap();
    stream.finish().unwrap();
    let output = std::str::from_utf8(&bytes).unwrap();
    assert!(output.contains("file&#9;&#13;&#10;&lt;&amp;&gt;&quot;.html"));
    assert!(output.contains("&#9;line&#13;&#10;中文🙂 &lt;&amp;&gt; &quot;quoted&quot;"));
    document.text.push('\u{1}');
    assert!(write_article(&mut Vec::new(), &document, ArticleFormat::Tei).is_err());
}

#[test]
fn json_and_csv_are_streamed_without_losing_document_or_record_boundaries() {
    let document = document();
    let mut bytes = Vec::new();
    let mut stream = ArticleStream::begin(&mut bytes, ArticleFormat::Json).unwrap();
    stream.push("a", &document).unwrap();
    stream.push("b", &document).unwrap();
    stream.finish().unwrap();
    let records: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(records.as_array().unwrap().len(), 2);
    assert_eq!(records[0]["document"]["text"], document.text);
    bytes.clear();
    let mut stream = ArticleStream::begin(&mut bytes, ArticleFormat::Csv).unwrap();
    stream.push("=source", &document).unwrap();
    stream.push("next", &document).unwrap();
    stream.finish().unwrap();
    let output = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(output.matches("source,title,source_url,text,comments").count(), 1);
    assert!(output.contains("\"'=source\""));
    assert_eq!(output.matches("\"' \t@formula\"").count(), 2);
    assert_eq!(output.matches("\"'=SUM(1,2)\"").count(), 2);
}

#[test]
fn text_framing_counts_utf8_bytes_not_scalars_and_cannot_be_spoofed() {
    let mut document = document();
    document.text = "🙂\n\u{1e}999 \"fake\"\n".to_owned();
    let mut bytes = Vec::new();
    let mut stream = ArticleStream::begin(&mut bytes, ArticleFormat::Text).unwrap();
    stream.push("a\n\"source", &document).unwrap();
    stream.finish().unwrap();
    let prefix = format!("\u{1e}{} \"a\\n\\\"source\"\n", document.text.len());
    assert!(bytes.starts_with(prefix.as_bytes()));
    assert_eq!(&bytes[prefix.len()..bytes.len() - 1], document.text.as_bytes());
}

#[test]
fn csv_formula_guard_keeps_bom_and_controls_but_neutralizes_the_formula() {
    let mut document = document();
    document.comments = "\u{feff}\u{0}=1+2".to_owned();
    let mut bytes = Vec::new();
    write_article(&mut bytes, &document, ArticleFormat::Csv).unwrap();
    assert!(std::str::from_utf8(&bytes)
        .unwrap()
        .contains("\"'\u{feff}\u{0}=1+2\""));
}

#[test]
fn invalid_xml_record_writes_nothing_and_does_not_corrupt_valid_siblings() {
    let good = document();
    let mut bad = document();
    bad.text.push('\u{1}');
    let mut bytes = Vec::new();
    let mut stream = ArticleStream::begin(&mut bytes, ArticleFormat::Xml).unwrap();
    assert!(stream.push("bad", &bad).is_err());
    assert!(stream.push("bad\u{1}source", &good).is_err());
    stream.push("good", &good).unwrap();
    stream.finish().unwrap();
    let output = String::from_utf8(bytes).unwrap();
    assert_eq!(output.matches("<entry source=").count(), 1);
    assert!(!output.contains("bad"));
    assert!(output.ends_with("</articles>\n"));
}
