#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use lopdf::content::Operation;
use lopdf::dictionary;

mod regressions;

const SECRET: &str = "native_pdf_secret_f41b8d";
const SAFE: &str = "Visible safe marker";

fn fixture(composite: bool) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let pages = doc.new_object_id();
    let font = if composite {
        let cmap = doc.add_object(Stream::new(Dictionary::new(), b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def /CMapName /Test def /CMapType 2 def 1 begincodespacerange <0000> <00FF> endcodespacerange 1 beginbfrange <0020> <007E> <0020> endbfrange endcmap CMapName currentdict /CMap defineresource pop end end".to_vec()));
        doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type0", "BaseFont" => "Test",
            "Encoding" => "Identity-H", "ToUnicode" => cmap,
            "DescendantFonts" => vec![Object::Dictionary(dictionary! {
                "Type" => "Font", "Subtype" => "CIDFontType2", "BaseFont" => "Test",
                "CIDSystemInfo" => dictionary! { "Registry" => Object::string_literal("Adobe"), "Ordering" => Object::string_literal("Identity"), "Supplement" => 0 },
            })],
        })
    } else {
        doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica", "Encoding" => "WinAnsiEncoding",
        })
    };
    let encode = |text: &str| {
        Object::String(
            if composite {
                text.encode_utf16().flat_map(u16::to_be_bytes).collect()
            } else {
                text.as_bytes().to_vec()
            },
            StringFormat::Hexadecimal,
        )
    };
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            // Preserve safe text even when a secret shares its text-show operand.
            Operation::new("Tj", vec![encode(&format!("{SAFE} {SECRET} tail"))]),
            Operation::new("Td", vec![0.into(), (-30).into()]),
            // A second occurrence is split across array strings and separate operations.
            Operation::new(
                "TJ",
                vec![Object::Array(vec![
                    encode("native_pdf_"),
                    0.into(),
                    encode("secret_"),
                ])],
            ),
            Operation::new("Tj", vec![encode("f41b8d")]),
            Operation::new("ET", vec![]),
        ],
    };
    let stream = doc.add_object(Stream::new(Dictionary::new(), content.encode().unwrap()));
    let uri = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Link", "Rect" => vec![0.into(), 0.into(), 100.into(), 100.into()],
        "A" => dictionary! { "S" => "URI", "URI" => Object::string_literal(format!("https://example.test/?token={SECRET}&id=3")) },
    });
    let info = doc.add_object(dictionary! {
        "Title" => Object::string_literal(format!("{SAFE} {SECRET}")),
        "Password" => Object::string_literal("unregistered-field-value"),
    });
    let page = doc.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages, "Contents" => stream,
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font } },
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Annots" => vec![Object::Reference(uri)],
    });
    doc.objects.insert(
        pages,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page)], "Count" => 1,
        }),
    );
    let metadata = doc.add_object(Stream::new(
        dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
        b"<x:meta xmlns:x=\"urn:test\"><x:title>Visible safe marker native_pdf_&#x73;ecret_f41b8d</x:title><x:password>unregistered-value</x:password><x:link href=\"https://example.test/?token=native_pdf_secret_f41b8d&amp;id=3\"/></x:meta>".to_vec(),
    ));
    let catalog =
        doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages, "Metadata" => metadata });
    doc.trailer.set("Root", catalog);
    doc.trailer.set("Info", info);
    doc.compress();
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

fn redact(text: &str) -> Result<String, ParseError> {
    let redactor = crawlx_core::secret::Redactor::new();
    let bytes = redactor.scrub_bytes(text.as_bytes(), [SECRET]);
    Ok(std::str::from_utf8(&bytes).unwrap().to_owned())
}

#[test]
fn native_pdf_redaction_rebuilds_xref_preserves_safe_text_and_pages() {
    for composite in [false, true] {
        let original = fixture(composite);
        let clean = sanitize_pdf(&original, &ParseLimits::default(), &redact).unwrap();
        assert!(clean.starts_with(b"%PDF-"));
        assert!(!clean
            .windows(SECRET.len())
            .any(|bytes| bytes == SECRET.as_bytes()));
        let parsed =
            crate::parse::pdf::extract_pdf(&clean, &crate::parse::pdf::PdfOptions::default()).unwrap();
        assert_eq!(parsed.total_pages, 1);
        assert!(parsed.text.contains(SAFE), "{}", parsed.text);
        assert!(parsed.text.contains("tail"));
        assert!(!parsed.text.contains(SECRET));
        assert_eq!(
            parsed.metadata.title.as_deref(),
            Some("Visible safe marker [REDACTED]")
        );
        assert_eq!(parsed.links.len(), 1);
        assert!(parsed.links[0].contains("[REDACTED]"));
        assert!(parsed.links[0].contains("id=3"));
        assert!(!parsed.links[0].contains(SECRET));
        let doc = Document::load_mem_with_options(
            &clean,
            LoadOptions {
                strict: true,
                ..LoadOptions::default()
            },
        )
        .unwrap();
        assert_eq!(doc.xref_recovery, None);
        let info = doc.trailer.get_deref(b"Info", &doc).unwrap().as_dict().unwrap();
        assert_eq!(
            lopdf::decode_text_string(info.get(b"Password").unwrap()).unwrap(),
            "[REDACTED]"
        );
        // Verify the actual serialized xref pointer, not merely lopdf's repair-tolerant load.
        let marker = b"startxref\n";
        let position = clean
            .windows(marker.len())
            .rposition(|window| window == marker)
            .unwrap();
        let offset = std::str::from_utf8(&clean[position + marker.len()..])
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert!(clean[offset..].starts_with(b"xref"));
        for (id, entry) in &doc.reference_table.entries {
            if let lopdf::xref::XrefEntry::Normal { offset, generation } = entry {
                let offset = usize::try_from(*offset).unwrap();
                assert!(clean[offset..].starts_with(format!("{id} {generation} obj").as_bytes()));
            }
        }
        for (id, object) in &doc.objects {
            if let Object::Stream(stream) = object {
                let decoded = stream
                    .decompressed_content()
                    .unwrap_or_else(|_| stream.content.clone());
                assert!(
                    !decoded
                        .windows(SECRET.len())
                        .any(|bytes| bytes == SECRET.as_bytes()),
                    "object {id:?}"
                );
            }
        }
        assert_eq!(
            sanitize_pdf(&original, &ParseLimits::default(), &redact).unwrap(),
            clean
        );
    }
}

#[test]
fn pdf_sanitization_rejects_malformed_input_and_hard_limits() {
    assert!(sanitize_pdf(b"%PDF-1.7\nnot a document", &ParseLimits::default(), &redact).is_err());
    let bytes = fixture(false);
    let limits = ParseLimits {
        max_input_bytes: 8,
        ..ParseLimits::default()
    };
    assert!(matches!(
        sanitize_pdf(&bytes, &limits, &redact),
        Err(ParseError::TooLarge { .. })
    ));
    let limits = ParseLimits {
        max_uncompressed_bytes: 32,
        ..ParseLimits::default()
    };
    assert!(matches!(
        sanitize_pdf(&bytes, &limits, &redact),
        Err(ParseError::TooLarge { .. })
    ));
    let limits = ParseLimits {
        max_pages: 0,
        ..ParseLimits::default()
    };
    assert!(matches!(
        sanitize_pdf(&bytes, &limits, &redact),
        Err(ParseError::TooLarge { .. })
    ));
}

#[test]
fn safe_native_pdf_keeps_original_text_and_geometry() {
    let original = fixture(true);
    let clean = sanitize_pdf(&original, &ParseLimits::default(), &|text| Ok(text.to_owned())).unwrap();
    let before =
        crate::parse::pdf::extract_pdf(&original, &crate::parse::pdf::PdfOptions::default()).unwrap();
    let after = crate::parse::pdf::extract_pdf(&clean, &crate::parse::pdf::PdfOptions::default()).unwrap();
    assert_eq!(after.text, before.text);
    assert_eq!(after.total_pages, before.total_pages);
    let before = Document::load_mem(&original).unwrap();
    let after = Document::load_mem(&clean).unwrap();
    let before_page = *before.get_pages().get(&1).unwrap();
    let after_page = *after.get_pages().get(&1).unwrap();
    assert_eq!(
        before
            .get_dictionary(before_page)
            .unwrap()
            .get(b"MediaBox")
            .unwrap(),
        after
            .get_dictionary(after_page)
            .unwrap()
            .get(b"MediaBox")
            .unwrap()
    );
}

#[test]
fn pdf_sanitization_decodes_escaped_actual_text_utf16_and_form_content() {
    let mut doc = Document::load_mem(&fixture(false)).unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    let resources = doc
        .get_dictionary(page)
        .unwrap()
        .get(b"Resources")
        .unwrap()
        .clone();
    let form = doc.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form", "FormType" => 1,
            "BBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => resources,
        },
        format!("BT /F1 12 Tf ({SECRET}) Tj ET").into_bytes(),
    ));
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .get_mut(b"Resources")
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("XObject", dictionary! { "SecretForm" => form });
    let stream = doc.add_object(Stream::new(Dictionary::new(),
        b"/Span << /ActualText (native_pdf_\\163ecret_f41b8d) >> BDC BT /F1 12 Tf 72 720 Td (Visible safe marker) Tj ET EMC /SecretForm Do".to_vec()));
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Contents", stream);
    let mut utf16 = vec![0xfe, 0xff];
    utf16.extend(
        format!("{SAFE} {SECRET}")
            .encode_utf16()
            .flat_map(u16::to_be_bytes),
    );
    let info_id = doc.trailer.get(b"Info").unwrap().as_reference().unwrap();
    doc.get_object_mut(info_id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Title", Object::String(utf16, StringFormat::Hexadecimal));
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    let clean = sanitize_pdf(&bytes, &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem_with_options(
        &clean,
        LoadOptions {
            strict: true,
            ..LoadOptions::default()
        },
    )
    .unwrap();
    let form = loaded.get_object(form).unwrap().as_stream().unwrap();
    let form_ops = Content::decode(&form.content).unwrap();
    assert!(form_ops
        .operations
        .iter()
        .filter(|op| op.operator == "Tj")
        .all(|op| op.operands[0].as_str().unwrap().is_empty()));
    let page = *loaded.get_pages().get(&1).unwrap();
    let ops = Content::decode(&loaded.get_page_content(page)).unwrap();
    let property = ops.operations.iter().find(|op| op.operator == "BDC").unwrap();
    let actual = property.operands[1]
        .as_dict()
        .unwrap()
        .get(b"ActualText")
        .unwrap();
    assert_eq!(lopdf::decode_text_string(actual).unwrap(), "[REDACTED]");
    let parsed = crate::parse::pdf::extract_pdf(&clean, &crate::parse::pdf::PdfOptions::default()).unwrap();
    assert!(parsed.text.contains(SAFE));
    assert!(!parsed.text.contains(SECRET));
    assert_eq!(
        parsed.metadata.title.as_deref(),
        Some("Visible safe marker [REDACTED]")
    );
}

#[test]
fn metadata_xml_sanitization_keeps_well_formed_escaped_structure() {
    let clean = sanitize_xml(
        b"<root title=\"native_pdf_&#x73;ecret_f41b8d &amp; safe\"><text>Visible safe marker native_pdf_&#x73;ecret_f41b8d</text><password>unregistered-value</password></root>",
        4096, &redact,
    ).unwrap();
    let text = std::str::from_utf8(&clean).unwrap();
    assert!(text.contains("Visible safe marker [REDACTED]"));
    assert!(text.contains("<password>[REDACTED]</password>"), "{text}");
    assert!(text.contains("title=\"[REDACTED] &amp; safe\""));
    assert!(!text.contains(SECRET));
    let mut reader = quick_xml::Reader::from_reader(clean.as_slice());
    loop {
        if matches!(reader.read_event().unwrap(), quick_xml::events::Event::Eof) {
            break;
        }
    }
}

#[test]
fn tiny_cmap_cannot_expand_an_unbounded_reverse_font_map() {
    let mut doc = Document::with_version("1.7");
    let cmap = doc.add_object(Stream::new(
        Dictionary::new(),
        b"1 beginbfrange <00000000> <7FFFFFFF> <0020> endbfrange".to_vec(),
    ));
    let font = dictionary! { "Type" => "Font", "ToUnicode" => cmap };
    let mut budget = Budget {
        remaining: 1_000_000,
        limit: 1_000_000,
    };
    let mut objects = ParseLimits::default().max_entries;
    assert!(matches!(
        bound_font_cmap(&doc, &font, &mut budget, &mut objects),
        Err(ParseError::TooLarge {
            what: "PDF CMap entries",
            ..
        }),
    ));
}
