#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::captcha::CaptchaSecrets;
use crate::SecretOr;

fn inspect(
    secrets: &CaptchaSecrets,
    mode: SecretScanMode,
    bytes: &[u8],
    split: usize,
) -> Result<(), SecretScanError> {
    let mut scanner = secrets.scoped_byte_scanner(mode, SecretScanLimits::new(1024 * 1024))?;
    scanner.push(&bytes[..split])?;
    scanner.push(&bytes[split..])?;
    scanner.finish()
}

fn registry(value: &str) -> CaptchaSecrets {
    let secrets = CaptchaSecrets::default();
    secrets.register(SecretOr::secret(value.to_owned())).unwrap();
    secrets
}

#[test]
fn raw_and_decoded_literals_survive_every_chunk_boundary() {
    let secrets = registry("private-🦀-token");
    for bytes in [
        "prefix private-🦀-token suffix".as_bytes(),
        br#"{"text":"private-\ud83e\udd80-token"}"#,
        br#"{"private-\uD83E\uDD80-token":null}"#,
        br#"{"text":"private-%F0%9F%A6%80-token"}"#,
        "{\"text\":\"private-🦀-token\"}".as_bytes(),
    ] {
        for split in 0..=bytes.len() {
            assert_eq!(
                inspect(&secrets, SecretScanMode::Auto, bytes, split),
                Err(SecretScanError::Secret)
            );
        }
    }
}

#[test]
fn one_byte_chunks_decode_utf8_surrogates_and_escapes() {
    for value in ["🦀", "é", "\n\r\t\u{0008}\u{000c}\\/\""] {
        let secrets = registry(value);
        let json = serde_json::to_vec(value).unwrap();
        let mut scanner = secrets
            .scoped_byte_scanner(SecretScanMode::Json, SecretScanLimits::new(4096))
            .unwrap();
        let mut result = Ok(());
        for byte in &json {
            result = scanner.push(std::slice::from_ref(byte));
            if result.is_err() {
                break;
            }
        }
        assert_eq!(
            result.and_then(|()| scanner.finish()),
            Err(SecretScanError::Secret)
        );
    }
    let secrets = registry("ab🦀cd");
    let mut scanner = secrets
        .scoped_byte_scanner(SecretScanMode::Json, SecretScanLimits::new(4096))
        .unwrap();
    for &byte in br#""ab\ud83e\udd80cd""# {
        scanner.push(&[byte]).unwrap();
    }
    assert_eq!(scanner.finish(), Err(SecretScanError::Secret));
}

#[test]
fn duplicate_names_compare_decoded_bytes_at_every_depth() {
    let secrets = CaptchaSecrets::default();
    for bytes in [
        br#"{"data":1,"d\u0061ta":2}"#.as_slice(),
        br#"{"nested":[{"x":1,"x":2}]}"#,
        br#"{"\ud83e\udd80":1,"\uD83E\uDD80":2}"#,
        "{\"🦀\":1,\"\\ud83e\\udd80\":2}".as_bytes(),
        br#"{"":1,"":2}"#,
    ] {
        for split in 0..=bytes.len() {
            assert_eq!(
                inspect(&secrets, SecretScanMode::Auto, bytes, split),
                Err(SecretScanError::DuplicateName)
            );
        }
    }
}

#[test]
fn repeated_names_in_different_objects_are_not_duplicates() {
    let secrets = CaptchaSecrets::default();
    let input = br#"{"data":1,"nested":{"data":2},"array":[{"data":3},{"data":4}]}"#;
    for split in 0..=input.len() {
        inspect(&secrets, SecretScanMode::Json, input, split).unwrap();
    }
}

#[test]
fn auto_preserves_non_json_binary_policy() {
    let secrets = registry("private-token");
    for input in [
        b"\xff\x00native binary".as_slice(),
        br#"image{\"x\":\"private-\u0074oken\"}"#,
        br#"{"x":"private-\u0074oken"}garbage"#,
        br#"{"x":"private-\u0074oken""#,
        b"",
    ] {
        for split in 0..=input.len() {
            assert!(!secrets.contains_bytes(input).unwrap());
            inspect(&secrets, SecretScanMode::Auto, input, split).unwrap();
        }
    }
    let input = br#"{"x":"private-\u0074oken"}"#;
    assert_eq!(
        inspect(&secrets, SecretScanMode::Auto, input, 8),
        Err(SecretScanError::Secret)
    );
    assert_eq!(
        inspect(&secrets, SecretScanMode::Json, input, 8),
        Err(SecretScanError::Secret)
    );
}

#[test]
fn malformed_json_never_receives_required_json_approval() {
    let secrets = CaptchaSecrets::default();
    for input in [
        b"".as_slice(),
        b"{",
        b"[1,]",
        b"{\"a\":1,}",
        b"01",
        b"1.",
        b"1e+",
        b"+1",
        b"-",
        b"true false",
        b"nullx",
        b"{]",
        b"[}",
        b"[1 2]",
        b"{\"a\" 1}",
        br#""\ud800""#,
        br#""\udc00""#,
        br#""\ud800\u0000""#,
        br#""\ud800x""#,
        b"\"\xc0\x80\"",
        b"\"\xed\xa0\x80\"",
        b"\"\xf4\x90\x80\x80\"",
        b"\"\xe2\"",
        b"\"\xff\"",
        b"\"a\x01b\"",
        br#""\x20""#,
    ] {
        for split in 0..=input.len() {
            assert_eq!(
                inspect(&secrets, SecretScanMode::Json, input, split),
                Err(SecretScanError::InvalidJson)
            );
        }
    }
}

#[test]
fn complete_json_grammar_accepts_all_value_kinds_and_whitespace() {
    let secrets = CaptchaSecrets::default();
    for input in [
        b"null".as_slice(),
        b"true",
        b"false",
        b"0",
        b"-0",
        b"-12.345e+20",
        b"1E-3",
        br#""plain \" \\ \/ \b \f \n \r \t \u0000 \ud83e\udd80""#,
        br#"{"array":[null,true,false,-2,3,4.5,"decoded\u0020value"],"nested":{}}"#,
        b" \r\n\t [ ] \r\n\t",
    ] {
        for split in 0..=input.len() {
            inspect(&secrets, SecretScanMode::Json, input, split).unwrap();
        }
    }
}

#[test]
fn fixed_limits_poison_scanner_without_downgrading_to_binary() {
    let secrets = CaptchaSecrets::default();
    let mut limits = SecretScanLimits::new(128);
    limits.max_depth = 1;
    let mut scanner = secrets.scoped_byte_scanner(SecretScanMode::Auto, limits).unwrap();
    assert_eq!(scanner.push(b"[["), Err(SecretScanError::Limit));
    assert_eq!(scanner.push(b"]]"), Err(SecretScanError::Aborted));
    assert_eq!(scanner.finish(), Err(SecretScanError::Aborted));

    limits.max_depth = 128;
    limits.max_keys = 1;
    let mut scanner = secrets.scoped_byte_scanner(SecretScanMode::Auto, limits).unwrap();
    assert_eq!(scanner.push(br#"{"a":1,"b":2}"#), Err(SecretScanError::Limit));

    limits.max_keys = 4096;
    limits.max_key_bytes = 3;
    let mut scanner = secrets.scoped_byte_scanner(SecretScanMode::Auto, limits).unwrap();
    assert_eq!(scanner.push(br#"{"ab":{"cd":1}}"#), Err(SecretScanError::Limit));

    let mut scanner = secrets
        .scoped_byte_scanner(SecretScanMode::Auto, SecretScanLimits::new(3))
        .unwrap();
    scanner.push(b"abc").unwrap();
    assert_eq!(scanner.push(b"d"), Err(SecretScanError::Limit));
}

#[test]
fn closed_objects_release_duplicate_bookkeeping_budget() {
    let secrets = CaptchaSecrets::default();
    let mut limits = SecretScanLimits::new(4096);
    limits.max_keys = 1;
    limits.max_key_bytes = 1;
    let mut scanner = secrets.scoped_byte_scanner(SecretScanMode::Json, limits).unwrap();
    scanner.push(br#"[{"a":1},{"b":2},{"c":3}]"#).unwrap();
    scanner.finish().unwrap();
}

#[test]
fn large_string_values_do_not_consume_key_budget() {
    let secrets = registry("not-present");
    let mut limits = SecretScanLimits::new(2 * 1024 * 1024);
    limits.max_key_bytes = 1;
    let mut scanner = secrets.scoped_byte_scanner(SecretScanMode::Json, limits).unwrap();
    scanner.push(br#"{"a":""#).unwrap();
    for _ in 0..1024 {
        scanner.push(&[b'x'; 1024]).unwrap();
    }
    scanner.push(br#""}"#).unwrap();
    scanner.finish().unwrap();
}

#[test]
fn decoded_matches_do_not_cross_distinct_json_strings() {
    let secrets = registry("firstsecond");
    let input = br#"["first","second"]"#;
    for split in 0..=input.len() {
        inspect(&secrets, SecretScanMode::Json, input, split).unwrap();
    }
}

#[test]
fn prefix_fallback_handles_overlapping_literals() {
    let secrets = registry("ababac");
    for input in [b"ababababac".as_slice(), br#""ababab\u0061bac""#] {
        for split in 0..=input.len() {
            assert_eq!(
                inspect(&secrets, SecretScanMode::Auto, input, split),
                Err(SecretScanError::Secret)
            );
        }
    }
}

#[test]
fn scanner_is_snapshot_not_registration_or_publication_authority() {
    let secrets = CaptchaSecrets::default();
    let mut scanner = secrets
        .scoped_byte_scanner(SecretScanMode::Auto, SecretScanLimits::new(4096))
        .unwrap();
    secrets
        .register(SecretOr::secret("registered-later".into()))
        .unwrap();
    scanner.push(b"registered-later").unwrap();
    scanner.finish().unwrap();
    assert!(secrets.contains_bytes(b"registered-later").unwrap());
    // Storage must recheck the exact epoch. This success grants no SecretFree token.
}

#[test]
fn dropping_partial_state_never_creates_approval_or_background_work() {
    let secrets = registry("private-token");
    let mut scanner = secrets
        .scoped_byte_scanner(SecretScanMode::Json, SecretScanLimits::new(4096))
        .unwrap();
    scanner.push(br#"{"name":"private-\u0074"#).unwrap();
    drop(scanner);
    let mut scanner = secrets
        .scoped_byte_scanner(SecretScanMode::Json, SecretScanLimits::new(4096))
        .unwrap();
    scanner.push(b"null").unwrap();
    scanner.finish().unwrap();
}

#[test]
fn scoped_scan_does_not_replace_global_secretfree_policy() {
    let secrets = CaptchaSecrets::default();
    let input = br#"{"authorization":"Bearer unregistered-value"}"#;
    inspect(&secrets, SecretScanMode::Json, input, 0).unwrap();
    assert!(crate::secret::Redactor::new().verify_binary(input).is_err());
}

#[test]
fn decoded_key_growth_preserves_bytes_and_only_replaces_full_buffers() {
    let maximum = 257;
    let mut key = Zeroizing::new(Vec::new());
    for size in 0..maximum {
        let address = key.as_ptr();
        let capacity = key.capacity();
        push_secret_byte(&mut key, b'x', maximum).unwrap();
        assert_eq!(key.as_slice(), vec![b'x'; size + 1]);
        if size < capacity {
            assert_eq!(address, key.as_ptr());
        } else {
            // Replacement is allocated while the old allocation is still live.
            assert_ne!(address, key.as_ptr());
            assert!(key.capacity() > capacity);
        }
    }
    assert_eq!(
        push_secret_byte(&mut key, b'y', maximum),
        Err(SecretScanError::Limit)
    );
    assert_eq!(key.as_slice(), vec![b'x'; maximum]);
}

#[test]
fn long_decoded_duplicate_keys_cross_multiple_secure_growth_boundaries() {
    let secrets = CaptchaSecrets::default();
    let plain = "a".repeat(257);
    let escaped = "\\u0061".repeat(257);
    let input = format!(r#"{{"{plain}":1,"{escaped}":2}}"#);
    let mut scanner = secrets
        .scoped_byte_scanner(SecretScanMode::Json, SecretScanLimits::new(4096))
        .unwrap();
    let result = input
        .as_bytes()
        .iter()
        .try_for_each(|byte| scanner.push(std::slice::from_ref(byte)));
    assert_eq!(result, Err(SecretScanError::DuplicateName));
    assert_eq!(scanner.finish(), Err(SecretScanError::Aborted));
}
