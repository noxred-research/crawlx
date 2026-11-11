//! `ExtractOptions::decode` and `ExtractOptions::markup` through `Extractor::extract_bytes`.
//! Omission must leave the document identical to the legacy lossy path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_extract::{
    decode::{DecodeOptions, EncodingSource, MarkupRetention},
    ExtractOptions, Extractor,
};
use url::Url;

fn base() -> Url {
    Url::parse("https://fixture.test/").unwrap()
}

const LATIN1: &[u8] = b"<html><head><meta charset=iso-8859-1><title>Caf\xe9</title></head>\
    <body><p>Le caf\xe9 est ouvert depuis le matin pour tous les voisins du quartier.</p></body></html>";

#[test]
fn omitted_options_keep_the_legacy_lossy_document_byte_identical() {
    let legacy = Extractor::extract_bytes(LATIN1, &base(), &ExtractOptions::default()).unwrap();
    assert!(legacy.decode.is_none() && legacy.markup.is_none());
    assert!(legacy.text.contains('\u{FFFD}'));
    let explicit_none = ExtractOptions {
        decode: None,
        markup: None,
        ..ExtractOptions::default()
    };
    let again = Extractor::extract_bytes(LATIN1, &base(), &explicit_none).unwrap();
    assert_eq!(legacy, again);
    let json = serde_json::to_string(&legacy).unwrap();
    assert!(
        !json.contains("\"decode\"") && !json.contains("\"markup\""),
        "{json}"
    );
}

#[test]
fn meta_charset_decodes_and_reports_diagnostics() {
    let options = ExtractOptions {
        decode: Some(DecodeOptions::default()),
        ..ExtractOptions::default()
    };
    let doc = Extractor::extract_bytes(LATIN1, &base(), &options).unwrap();
    assert!(doc.text.contains("Le café est ouvert"), "{}", doc.text);
    assert_eq!(doc.title.as_deref(), Some("Café"));
    let report = doc.decode.unwrap();
    assert_eq!(report.source, EncodingSource::Meta);
    assert_eq!(report.issue_count, 0);
    assert!(report.encoding.to_ascii_lowercase().contains("1252"));
    // The raw digest still covers the original bytes.
    let legacy = Extractor::extract_bytes(LATIN1, &base(), &ExtractOptions::default()).unwrap();
    assert_eq!(doc.raw_html_digest, legacy.raw_html_digest);
}

#[test]
fn declared_charset_and_content_type_beat_meta_and_a_bom_beats_both() {
    let body = b"<html><body><p>Gr\xfc\xdfe aus dem Dorf am See, geschrieben f\xfcr alle Nachbarn im Tal.</p></body></html>";
    let declared = ExtractOptions {
        decode: Some(DecodeOptions::with_charset("windows-1252")),
        ..ExtractOptions::default()
    };
    let doc = Extractor::extract_bytes(body, &base(), &declared).unwrap();
    assert!(doc.text.contains("Grüße"), "{}", doc.text);
    assert_eq!(doc.decode.as_ref().unwrap().source, EncodingSource::Declared);

    let from_header = ExtractOptions {
        decode: Some(DecodeOptions::default()),
        content_type: Some("text/html; charset=ISO-8859-1".into()),
        ..ExtractOptions::default()
    };
    let doc = Extractor::extract_bytes(body, &base(), &from_header).unwrap();
    assert!(doc.text.contains("Grüße"));
    assert_eq!(doc.decode.as_ref().unwrap().source, EncodingSource::Declared);

    let mut with_bom = vec![0xef, 0xbb, 0xbf];
    with_bom.extend_from_slice("<p>Grüße aus dem Dorf am See, geschrieben für alle Nachbarn.</p>".as_bytes());
    let doc = Extractor::extract_bytes(&with_bom, &base(), &declared).unwrap();
    assert!(doc.text.contains("Grüße"));
    let report = doc.decode.unwrap();
    assert_eq!(report.source, EncodingSource::Bom);
    assert!(report.declaration_conflict);
}

#[test]
fn malformed_bytes_are_recorded_not_hidden() {
    let options = ExtractOptions {
        decode: Some(DecodeOptions::default()),
        ..ExtractOptions::default()
    };
    let body = b"<p>valid text before \xff\xfe and after the broken bytes, long enough to keep.</p>";
    let doc = Extractor::extract_bytes(body, &base(), &options).unwrap();
    let report = doc.decode.unwrap();
    assert_eq!(report.issue_count, 2);
    assert_eq!(report.issues[0].offset, 21);
    assert!(doc.text.contains("valid text before"));
}

#[test]
fn markup_retention_collects_comments_and_cdata_beside_unchanged_text() {
    let html = "<html><body><p>Visible paragraph text that is long enough to stay in the output.</p>\
        <!-- editor note --><![CDATA[raw & payload]]><p>Second paragraph, also visible to readers.</p></body></html>";
    let plain = Extractor::extract(html, &base(), &ExtractOptions::default()).unwrap();
    let options = ExtractOptions {
        markup: Some(MarkupRetention::all()),
        ..ExtractOptions::default()
    };
    let kept = Extractor::extract(html, &base(), &options).unwrap();
    let record = kept.markup.clone().unwrap();
    assert_eq!(record.comments, [" editor note "]);
    assert_eq!(record.cdata, ["raw & payload"]);
    assert!(!record.truncated);
    // The cleaned view is untouched; only the separate record appears.
    assert_eq!(kept.text, plain.text);
    assert_eq!(kept.markdown, plain.markdown);
    assert!(!kept.text.contains("editor note"));

    let comments_only = ExtractOptions {
        markup: Some(MarkupRetention::default()),
        ..ExtractOptions::default()
    };
    assert!(Extractor::extract(html, &base(), &comments_only)
        .unwrap()
        .markup
        .is_none());
    let only_cdata = ExtractOptions {
        markup: serde_json::from_str(r#"{"cdata":true}"#).unwrap(),
        ..ExtractOptions::default()
    };
    let record = Extractor::extract(html, &base(), &only_cdata)
        .unwrap()
        .markup
        .unwrap();
    assert!(record.comments.is_empty());
    assert_eq!(record.cdata, ["raw & payload"]);
}

#[test]
fn decode_and_markup_compose_and_digest_the_decoded_source() {
    let options = ExtractOptions {
        decode: Some(DecodeOptions::default()),
        markup: Some(MarkupRetention::all()),
        ..ExtractOptions::default()
    };
    let bytes = b"<meta charset=iso-8859-1><!-- caf\xe9 --><p>Le caf\xe9 est ouvert pour tous les voisins du quartier.</p>";
    let doc = Extractor::extract_bytes(bytes, &base(), &options).unwrap();
    let markup = doc.markup.unwrap();
    assert_eq!(markup.comments, [" café "]);
    let decoded = crawlx_extract::decode::decode(bytes, None).unwrap();
    assert_eq!(
        markup.source_digest,
        crawlx_core::hash::Digest::of("crawlx.extract.decoded_source.v1", decoded.text.as_bytes())
    );
}
