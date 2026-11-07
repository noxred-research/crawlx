#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn document() -> (Document, ObjectId, Dictionary) {
    let doc = Document::load_mem(&fixture(false)).unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    let resources = doc
        .get_dictionary(page)
        .unwrap()
        .get(b"Resources")
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    (doc, page, resources)
}

fn save(mut doc: Document) -> Vec<u8> {
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

fn replace_content(doc: &mut Document, page: ObjectId, bytes: Vec<u8>) {
    let id = doc.add_object(Stream::new(Dictionary::new(), bytes));
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Contents", id);
}

fn form(doc: &mut Document, resources: Dictionary, text: &str) -> ObjectId {
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(
                    text.as_bytes().to_vec(),
                    StringFormat::Hexadecimal,
                )],
            ),
            Operation::new("ET", vec![]),
        ],
    };
    doc.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form", "FormType" => 1,
            "BBox" => vec![0.into(), 0.into(), 200.into(), 100.into()], "Resources" => resources,
        },
        content.encode().unwrap(),
    ))
}

fn shown(content: &[u8]) -> String {
    let content = Content::decode_strict(content).unwrap();
    let mut text = String::new();
    for operation in content.operations {
        if operation.operator == "Tj" {
            text.push_str(std::str::from_utf8(operation.operands[0].as_str().unwrap()).unwrap());
        }
    }
    text
}

#[test]
fn widget_appearance_hex_text_is_sanitized_without_page_do() {
    let (mut doc, page, resources) = document();
    let appearance = form(&mut doc, resources, SECRET);
    let annotation = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Widget",
        "Rect" => vec![0.into(), 0.into(), 200.into(), 100.into()],
        "AP" => dictionary! { "N" => appearance },
    });
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Annots", vec![Object::Reference(annotation)]);
    assert_eq!(
        shown(&doc.get_object(appearance).unwrap().as_stream().unwrap().content),
        SECRET
    );
    let native = save(doc);
    let clean = sanitize_pdf(&native, &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem_with_options(
        &clean,
        LoadOptions {
            strict: true,
            ..LoadOptions::default()
        },
    )
    .unwrap();
    assert_eq!(
        shown(
            &loaded
                .get_object(appearance)
                .unwrap()
                .as_stream()
                .unwrap()
                .content
        ),
        ""
    );
    let parsed = crate::parse::pdf::extract_pdf(&clean, &crate::parse::pdf::PdfOptions::default()).unwrap();
    assert!(parsed.text.contains(SAFE));
    assert_eq!(parsed.total_pages, 1);
}

#[test]
fn parent_and_invoked_form_share_one_text_redaction_plane() {
    let (mut doc, page, resources) = document();
    let child = form(&mut doc, resources, "secret_f41b8d");
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .get_mut(b"Resources")
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("XObject", dictionary! { "Child" => child });
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 12.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(
                    format!("{SAFE} native_pdf_").into_bytes(),
                    StringFormat::Hexadecimal,
                )],
            ),
            Operation::new("ET", vec![]),
            Operation::new("Do", vec![Object::Name(b"Child".to_vec())]),
        ],
    };
    replace_content(&mut doc, page, content.encode().unwrap());
    assert!((shown(&doc.get_page_content(page))
        + &shown(&doc.get_object(child).unwrap().as_stream().unwrap().content))
        .contains(SECRET));
    let clean = sanitize_pdf(&save(doc), &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem_with_options(
        &clean,
        LoadOptions {
            strict: true,
            ..LoadOptions::default()
        },
    )
    .unwrap();
    let page = *loaded.get_pages().get(&1).unwrap();
    let visible = shown(&loaded.get_page_content(page))
        + &shown(&loaded.get_object(child).unwrap().as_stream().unwrap().content);
    assert!(visible.contains(SAFE));
    assert!(!visible.contains("native_pdf_"));
    assert!(!visible.contains("secret_f41b8d"));
}

fn expanding_font(doc: &mut Document, resources: &Dictionary) {
    let font = resources
        .get(b"Font")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"F1")
        .unwrap()
        .as_reference()
        .unwrap();
    let target = "4E00".repeat(256);
    let cmap = doc.add_object(Stream::new(Dictionary::new(), format!(
        "/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def /CMapName /Expanded def /CMapType 2 def 1 begincodespacerange <0000> <FFFF> endcodespacerange 1 beginbfrange <0001> <0001> <{target}> endbfrange endcmap CMapName currentdict /CMap defineresource pop end end"
    ).into_bytes()));
    let font = doc.get_object_mut(font).unwrap().as_dict_mut().unwrap();
    font.set("Subtype", "Type0");
    font.set("Encoding", "Identity-H");
    font.set("ToUnicode", cmap);
}

#[test]
fn unicode_expansion_is_charged_before_decoding_a_whole_operand() {
    let (mut doc, page, resources) = document();
    expanding_font(&mut doc, &resources);
    replace_content(
        &mut doc,
        page,
        format!("BT /F1 12 Tf <{}> Tj ET", "0001".repeat(4096)).into_bytes(),
    );
    let native = save(doc);
    let limits = ParseLimits {
        max_uncompressed_bytes: 64 * 1024,
        ..ParseLimits::default()
    };
    assert!(matches!(
        sanitize_pdf(&native, &limits, &redact),
        Err(ParseError::TooLarge { .. })
    ));
}

#[test]
fn repeated_form_unicode_expansion_uses_one_document_budget() {
    let (mut doc, page, resources) = document();
    expanding_font(&mut doc, &resources);
    let child = doc.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form", "FormType" => 1,
            "BBox" => vec![0.into(), 0.into(), 200.into(), 100.into()], "Resources" => resources,
        },
        format!("BT /F1 12 Tf <{}> Tj ET", "0001".repeat(32)).into_bytes(),
    ));
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .get_mut(b"Resources")
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("XObject", dictionary! { "Child" => child });
    replace_content(&mut doc, page, "/Child Do\n".repeat(32).into_bytes());
    let native = save(doc);
    let limits = ParseLimits {
        max_uncompressed_bytes: 128 * 1024,
        ..ParseLimits::default()
    };
    assert!(matches!(
        sanitize_pdf(&native, &limits, &redact),
        Err(ParseError::TooLarge { .. })
    ));
}

fn xml_value(bytes: &[u8]) -> String {
    let mut reader = quick_xml::Reader::from_reader(bytes);
    let mut value = String::new();
    loop {
        match reader.read_event().unwrap() {
            quick_xml::events::Event::Text(text) => value.push_str(&text.decode().unwrap()),
            quick_xml::events::Event::GeneralRef(reference) => {
                if let Some(ch) = reference.resolve_char_ref().unwrap() {
                    value.push(ch);
                } else {
                    value.push_str(
                        quick_xml::escape::resolve_xml_entity(&reference.decode().unwrap()).unwrap(),
                    );
                }
            }
            quick_xml::events::Event::CData(text) => value.push_str(&text.decode().unwrap()),
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
    }
    value
}

#[test]
fn pdf_metadata_string_value_matches_across_comments_and_cdata() {
    let (mut doc, _, _) = document();
    let metadata = doc.add_object(Stream::new(
        dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
        b"<root>Visible safe marker native_pdf_<!--split--><![CDATA[secret_]]>f41b8d</root>".to_vec(),
    ));
    let catalog = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_object_mut(catalog)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Metadata", metadata);
    assert!(xml_value(&doc.get_object(metadata).unwrap().as_stream().unwrap().content).contains(SECRET));
    let clean = sanitize_pdf(&save(doc), &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem_with_options(
        &clean,
        LoadOptions {
            strict: true,
            ..LoadOptions::default()
        },
    )
    .unwrap();
    let stream = loaded.get_object(metadata).unwrap().as_stream().unwrap();
    let value = xml_value(&stream.content);
    assert!(value.contains(SAFE));
    assert!(value.contains("[REDACTED]"));
    assert!(!value.contains(SECRET));
    assert!(!value.contains("secret_"));
}

#[test]
fn metadata_references_join_the_same_redaction_plane() {
    let xml = b"<root>Visible safe marker &amp; &#x1F642; native_pdf_&#115;ecret_f41b8d</root>";
    let clean = super::super::xml::sanitize_xml(xml, 1_048_576, &redact).unwrap();
    assert_eq!(xml_value(&clean), "Visible safe marker & 🙂 [REDACTED]");
    for bytes in [
        b"<root>&custom;</root>".as_slice(),
        b"<root>&#x110000;</root>".as_slice(),
        b"<root key='one' key='two'/>".as_slice(),
        b"<!DOCTYPE root><root/>".as_slice(),
    ] {
        assert!(super::super::xml::sanitize_xml(bytes, 1_048_576, &redact).is_err());
    }
}

fn inline_image_pdf(compressed: bool) -> Vec<u8> {
    let (mut doc, page, _) = document();
    let (size, pixels) = if compressed {
        (64, vec![0; 64 * 64 * 3])
    } else {
        (1, vec![0x11, 0x22, 0x33])
    };
    let mut image = Stream::new(
        dictionary! { "W" => size, "H" => size, "BPC" => 8, "CS" => "RGB" },
        pixels,
    );
    if compressed {
        image.compress().unwrap();
        assert_eq!(
            image.dict.get(b"Filter").unwrap().as_name().unwrap(),
            b"FlateDecode"
        );
    }
    let inline = Content {
        operations: vec![Operation::new("BI", vec![Object::Stream(image)])],
    }
    .encode()
    .unwrap();
    let mut bytes = doc.get_page_content(page);
    bytes.push(b'\n');
    bytes.extend(inline);
    replace_content(&mut doc, page, bytes);
    save(doc)
}

#[test]
fn unsupported_compressed_inline_image_is_not_emitted_as_bare_bi() {
    assert!(matches!(
        sanitize_pdf(&inline_image_pdf(true), &ParseLimits::default(), &redact),
        Err(ParseError::Corrupt { .. })
    ));
}

#[test]
fn supported_native_inline_image_pixels_and_safe_text_are_preserved() {
    let clean = sanitize_pdf(&inline_image_pdf(false), &ParseLimits::default(), &redact).unwrap();
    let doc = Document::load_mem_with_options(
        &clean,
        LoadOptions {
            strict: true,
            ..LoadOptions::default()
        },
    )
    .unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    let content = Content::decode_strict(&doc.get_page_content(page)).unwrap();
    let image = content
        .operations
        .iter()
        .find(|operation| operation.operator == "BI")
        .unwrap();
    let image = image.operands[0].as_stream().unwrap();
    assert_eq!(image.content, [0x11, 0x22, 0x33]);
    assert!(shown(&doc.get_page_content(page)).contains(SAFE));
}

fn attach_appearances(doc: &mut Document, page: ObjectId, forms: &[ObjectId]) {
    let mut annotations = Vec::new();
    for form in forms {
        let annotation = doc.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget",
            "Rect" => vec![0.into(), 0.into(), 200.into(), 100.into()],
            "AP" => dictionary! { "N" => Object::Reference(*form) },
        });
        annotations.push(Object::Reference(annotation));
    }
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Annots", annotations);
}

#[test]
fn annotation_paint_order_is_not_object_id_order() {
    let (mut doc, page, resources) = document();
    let suffix = form(&mut doc, resources.clone(), "secret_f41b8d");
    let prefix = form(&mut doc, resources, "native_pdf_");
    assert!(suffix < prefix);
    attach_appearances(&mut doc, page, &[prefix, suffix]);
    let clean = sanitize_pdf(&save(doc), &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem(&clean).unwrap();
    assert_eq!(
        shown(&loaded.get_object(prefix).unwrap().as_stream().unwrap().content),
        ""
    );
    assert_eq!(
        shown(&loaded.get_object(suffix).unwrap().as_stream().unwrap().content),
        ""
    );
}

#[test]
fn repeated_annotation_appearance_is_not_deduplicated() {
    let (mut doc, page, resources) = document();
    let repeated = form(&mut doc, resources, "abc");
    attach_appearances(&mut doc, page, &[repeated, repeated]);
    let redact = |text: &str| {
        let policy = crawlx_core::secret::Redactor::new();
        let clean = policy.scrub_bytes(text.as_bytes(), [SECRET, "abcabc"]);
        Ok(std::str::from_utf8(&clean).unwrap().to_owned())
    };
    let clean = sanitize_pdf(&save(doc), &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem(&clean).unwrap();
    assert_eq!(
        shown(&loaded.get_object(repeated).unwrap().as_stream().unwrap().content),
        ""
    );
}

#[test]
fn out_of_codespace_decoy_cannot_hide_a_multibyte_registered_secret() {
    let (mut doc, page, resources) = document();
    let font_id = resources
        .get(b"Font")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"F1")
        .unwrap()
        .as_reference()
        .unwrap();
    let fallback = doc.add_object(doc.get_object(font_id).unwrap().clone());
    let secret = SECRET
        .encode_utf16()
        .map(|unit| format!("{unit:04X}"))
        .collect::<String>();
    let cmap = doc.add_object(Stream::new(Dictionary::new(), format!(
        "/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def /CMapName /Decoy def /CMapType 2 def 1 begincodespacerange <0000> <FFFF> endcodespacerange 2 beginbfchar <41> <0058> <4141> <{secret}> endbfchar endcmap CMapName currentdict /CMap defineresource pop end end"
    ).into_bytes()));
    let font = doc.get_object_mut(font_id).unwrap().as_dict_mut().unwrap();
    font.set("Subtype", "Type0");
    font.set("Encoding", "Identity-H");
    font.set("ToUnicode", cmap);
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .get_mut(b"Resources")
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .get_mut(b"Font")
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("F2", fallback);
    replace_content(
        &mut doc,
        page,
        b"BT /F2 12 Tf 72 720 Td (Visible safe marker) Tj /F1 12 Tf <4141> Tj ET".to_vec(),
    );
    let native = save(doc);
    let before = crate::parse::pdf::extract_pdf(&native, &crate::parse::pdf::PdfOptions::default()).unwrap();
    assert!(before.text.contains(SECRET));
    let clean = sanitize_pdf(&native, &ParseLimits::default(), &redact).unwrap();
    let after = crate::parse::pdf::extract_pdf(&clean, &crate::parse::pdf::PdfOptions::default()).unwrap();
    assert!(after.text.contains(SAFE));
    assert!(!after.text.contains(SECRET));
    let loaded = Document::load_mem(&clean).unwrap();
    let retained = loaded.get_object(cmap).unwrap().as_stream().unwrap();
    let retained = std::str::from_utf8(&retained.content)
        .unwrap()
        .to_ascii_lowercase();
    assert!(!retained.contains(&secret.to_ascii_lowercase()));
}

#[test]
fn dense_content_operations_are_bounded_without_glyphs() {
    let (mut doc, page, _) = document();
    replace_content(&mut doc, page, "q Q ".repeat(2500).into_bytes());
    let limits = ParseLimits {
        max_uncompressed_bytes: 64 * 1024,
        ..ParseLimits::default()
    };
    assert!(matches!(
        sanitize_pdf(&save(doc), &limits, &redact),
        Err(ParseError::TooLarge { .. })
    ));
}

#[test]
fn removing_one_secret_does_not_create_another_from_neighboring_glyphs() {
    let (mut doc, page, _) = document();
    replace_content(
        &mut doc,
        page,
        b"BT /F1 12 Tf 72 720 Td (Visible safe marker abc MASK def) Tj ET".to_vec(),
    );
    let redact = |text: &str| {
        let policy = crawlx_core::secret::Redactor::new();
        let clean = policy.scrub_bytes(text.as_bytes(), [SECRET, " MASK ", "abcdef"]);
        Ok(std::str::from_utf8(&clean).unwrap().to_owned())
    };
    let clean = sanitize_pdf(&save(doc), &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem(&clean).unwrap();
    let page = *loaded.get_pages().get(&1).unwrap();
    let visible = shown(&loaded.get_page_content(page));
    assert!(visible.contains(SAFE));
    assert!(!visible.contains("MASK"));
    assert!(!visible.contains("abcdef"));
}

#[test]
fn unused_unicode_mapping_does_not_retain_an_encoded_secret_copy() {
    let mut doc = Document::load_mem(&fixture(true)).unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    let resources = doc
        .get_dictionary(page)
        .unwrap()
        .get(b"Resources")
        .unwrap()
        .as_dict()
        .unwrap();
    let font = resources
        .get(b"Font")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"F1")
        .unwrap()
        .as_reference()
        .unwrap();
    let cmap = doc
        .get_dictionary(font)
        .unwrap()
        .get(b"ToUnicode")
        .unwrap()
        .as_reference()
        .unwrap();
    let original = doc
        .get_object(cmap)
        .unwrap()
        .as_stream()
        .unwrap()
        .decompressed_content()
        .unwrap();
    let original = std::str::from_utf8(&original).unwrap();
    let secret = SECRET
        .encode_utf16()
        .map(|unit| format!("{unit:04X}"))
        .collect::<String>();
    let changed = original.replace(
        "endcmap",
        &format!("1 beginbfchar <FFFF> <{secret}> endbfchar endcmap"),
    );
    doc.get_object_mut(cmap)
        .unwrap()
        .as_stream_mut()
        .unwrap()
        .set_plain_content(changed.into_bytes());
    let clean = sanitize_pdf(&save(doc), &ParseLimits::default(), &redact).unwrap();
    let loaded = Document::load_mem_with_options(
        &clean,
        LoadOptions {
            strict: true,
            ..LoadOptions::default()
        },
    )
    .unwrap();
    let retained = loaded.get_object(cmap).unwrap().as_stream().unwrap();
    assert!(!std::str::from_utf8(&retained.content)
        .unwrap()
        .to_ascii_lowercase()
        .contains(&secret.to_ascii_lowercase()));
    let parsed = crate::parse::pdf::extract_pdf(&clean, &crate::parse::pdf::PdfOptions::default()).unwrap();
    assert!(parsed.text.contains(SAFE));
    assert!(!parsed.text.contains(SECRET));
}
