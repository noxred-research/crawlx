//! Behavioral regressions for bounded, strict content decoding.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use lopdf::{DecompressError, Error, Object, content::Content};

fn assert_limit(data: &[u8], objects: usize, bytes: usize, expected: usize) {
    assert!(matches!(
        Content::decode_bounded(data, objects, bytes),
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { limit })) if limit == expected
    ));
}

#[test]
fn operation_cap_rejects_before_collecting_a_long_stream() {
    let input = b"q Q ".repeat(100_000);
    assert_limit(&input, 1, usize::MAX, 1);
    assert_eq!(Content::decode_bounded(b"q", 1, 1024).unwrap().operations.len(), 1);
    assert_limit(b"q", 0, usize::MAX, 0);
    assert!(Content::decode_bounded(b" \n", 0, 0).unwrap().operations.is_empty());
}

#[test]
fn flat_operands_and_array_members_consume_node_budget() {
    let members = b"0 ".repeat(100_000);
    let mut flat = members.clone();
    flat.extend_from_slice(b"TJ");
    assert_limit(&flat, 8, usize::MAX, 8);

    let mut array = b"[".to_vec();
    array.extend_from_slice(&members);
    array.extend_from_slice(b"] TJ");
    assert_limit(&array, 8, usize::MAX, 8);
    assert_limit(&array, usize::MAX, 2048, 2048);
}

#[test]
fn dictionaries_and_nested_arrays_consume_node_budget() {
    let mut dictionary = b"<<".to_vec();
    dictionary.extend_from_slice(&b"/K 0 ".repeat(100_000));
    dictionary.extend_from_slice(b">> DP");
    // Repeated keys must not evade the syntax budget through replacement.
    assert_limit(&dictionary, 8, usize::MAX, 8);
    assert_limit(&dictionary, usize::MAX, 2048, 2048);

    let mut nested = b"[".repeat(64);
    nested.extend_from_slice(b"0");
    nested.extend_from_slice(&b"]".repeat(64));
    nested.extend_from_slice(b" TJ");
    assert_limit(&nested, 8, usize::MAX, 8);
    let decoded = Content::decode_bounded(&nested, 128, 64 * 1024).unwrap();
    assert_eq!(decoded.operations.len(), 1);
}

#[test]
fn excessive_nesting_fails_without_recursing_through_the_input() {
    for (open, close) in [(b'[', b']'), (b'(', b')')] {
        let mut input = vec![open; 100_000];
        input.extend(std::iter::repeat_n(close, 100_000));
        input.extend_from_slice(b" Tj");
        assert!(Content::decode_bounded(&input, usize::MAX, usize::MAX).is_err());
    }

    let mut dictionaries = b"<< /K ".repeat(10_000);
    dictionaries.extend_from_slice(b"0");
    dictionaries.extend_from_slice(&b" >>".repeat(10_000));
    dictionaries.extend_from_slice(b" DP");
    assert!(Content::decode_bounded(&dictionaries, usize::MAX, usize::MAX).is_err());
}

#[test]
fn ordinary_text_and_nested_objects_keep_existing_semantics() {
    let input = b"% leading\nq BT /F#31 12 Tf [(A\\n(B)) -120 <4344F>] TJ ET Q\n\
                  /P << /MCID 0 /Nested [true false null << /Ref 3 0 R >>] >> BDC EMC\n\
                  0.00-4142502 0 m % trailing\n";
    let ordinary = Content::decode_strict(input).unwrap();
    let bounded = Content::decode_bounded(input, 128, 64 * 1024).unwrap();
    assert_eq!(bounded.encode().unwrap(), ordinary.encode().unwrap());
}

#[test]
fn large_string_name_and_hexadecimal_leaves_are_bounded_without_node_amplification() {
    let payload = vec![b'A'; 1024 * 1024];
    for (prefix, suffix) in [(b"(".as_slice(), b") Tj".as_slice()), (b"/".as_slice(), b" Do".as_slice())] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(&payload);
        input.extend_from_slice(suffix);
        let decoded = Content::decode_bounded(&input, 2, 3 * payload.len()).unwrap();
        let actual = match &decoded.operations[0].operands[0] {
            Object::String(bytes, _) | Object::Name(bytes) => bytes,
            other => panic!("unexpected leaf: {other:?}"),
        };
        assert_eq!(actual, &payload);
        assert_limit(&input, 2, 1024, 1024);
    }

    let mut hexadecimal = b"<".to_vec();
    hexadecimal.extend_from_slice(&b"41".repeat(payload.len()));
    hexadecimal.extend_from_slice(b"> Tj");
    let decoded = Content::decode_bounded(&hexadecimal, 2, 2 * payload.len()).unwrap();
    assert_eq!(decoded.operations[0].operands[0].as_str().unwrap(), payload);
    assert_limit(&hexadecimal, 2, 1024, 1024);
}

#[test]
fn inline_image_roundtrip_preserves_binary_and_string_dictionary_leaves() {
    let input = b"q BI /W 10 /H 1 /BPC 8 /CS /G /Tag (sample) ID \x00\x01\x02 EI \xff\x00\x04\nEI Q";
    let decoded = Content::decode_bounded(input, 32, 16 * 1024).unwrap();
    let image = decoded.operations[1].operands[0].as_stream().unwrap();
    assert_eq!(image.content, b"\x00\x01\x02 EI \xff\x00\x04");
    assert_eq!(image.dict.get(b"Tag").unwrap().as_str().unwrap(), b"sample");
    let encoded = decoded.encode().unwrap();
    let roundtrip = Content::decode_bounded(&encoded, 32, 16 * 1024).unwrap();
    assert_eq!(roundtrip.operations[1].operands[0].as_stream().unwrap().content, image.content);
    assert_eq!(roundtrip.operations.len(), 3);
}

#[test]
fn large_inline_image_leaf_respects_byte_budget() {
    let payload = vec![b'X'; 128 * 1024];
    let mut input = format!("BI /W {} /H 1 /BPC 8 /CS /G ID ", payload.len()).into_bytes();
    input.extend_from_slice(&payload);
    input.extend_from_slice(b"\nEI");
    let decoded = Content::decode_bounded(&input, 16, payload.len() + 16 * 1024).unwrap();
    assert_eq!(decoded.operations[0].operands[0].as_stream().unwrap().content, payload);
    assert_limit(&input, 16, 4096, 4096);
    assert_limit(&input, 8, usize::MAX, 8);
}

#[test]
fn unsupported_and_truncated_inline_images_fail_closed() {
    let inputs: [&[u8]; 4] = [
        b"BI /W 1 /H 1 /BPC 8 /CS /G /F /Fl ID X EI q",
        b"BI /W 1 /H 1 /BPC 8 /CS /Unknown ID X EI q",
        b"BI /W 4 /H 1 /BPC 8 /CS /G ID X EI",
        b"BI /W 1 /H 1 /BPC 8 /CS /G ID X",
    ];
    for input in inputs {
        assert!(Content::decode_bounded(input, 64, 64 * 1024).is_err());
    }
}

#[test]
fn strict_decoder_rejects_trailing_junk_and_incomplete_operands() {
    for input in [b"q ) trailing".as_slice(), b"q (unterminated", b"q [1 2", b"q 42", b"q % no newline"] {
        assert!(Content::decode_bounded(input, 128, 64 * 1024).is_err());
    }
}

#[test]
fn returned_usage_supports_shared_budgets_and_exact_replay() {
    let input = b"BT /F1 12 Tf [(hello) -5 (world)] TJ ET";
    let (decoded, objects, bytes) = Content::decode_bounded_with_usage(input, 128, 64 * 1024).unwrap();
    let replay = Content::decode_bounded(input, objects, bytes).unwrap();
    assert_eq!(decoded.encode().unwrap(), replay.encode().unwrap());
    assert_limit(input, objects - 1, bytes, objects - 1);
    assert_limit(input, objects, bytes - 1, bytes - 1);
}
