//! Regex extraction admission: built-in names are versioned, custom patterns run on the
//! linear-time engine, and unsupported constructs are rejected before any text is scanned.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_extract::{
    custom_fields::{CustomField, CustomFieldError, CustomFieldSpec, Part},
    regex_builtins::{
        builtin, builtin_names, extract, CompiledPattern, RegexError, RegexPatternSpec,
        MAX_MATCHES_PER_PATTERN, PATTERN_TABLE_VERSION,
    },
};

#[test]
fn built_in_names_are_versioned_and_stable() {
    assert_eq!(PATTERN_TABLE_VERSION, 1);
    let names = builtin_names();
    for expected in [
        "currency.v1",
        "date_like.v1",
        "email.v1",
        "hashtag.v1",
        "ipv4.v1",
        "phone_like.v1",
        "url.v1",
        "uuid.v1",
    ] {
        assert!(names.iter().any(|n| n == expected), "{expected}");
    }
    assert_eq!(builtin("uuid").unwrap().versioned_name(), "uuid.v1");
    assert!(matches!(builtin("uuid.v2"), Err(RegexError::UnknownBuiltin(_))));
    assert!(matches!(builtin("uuid.vx"), Err(RegexError::UnknownBuiltin(_))));
}

#[test]
fn bounded_custom_pattern_succeeds_with_spans_and_groups() {
    let patterns = CompiledPattern::compile_all(&[
        RegexPatternSpec::custom("sku", r"SKU-(\d{4})", 1),
        RegexPatternSpec::builtin("email"),
    ])
    .unwrap();
    let text = "order SKU-0042 and SKU-1337 to ops@example.com";
    let out = extract(&patterns, text).unwrap();
    let skus: Vec<_> = out["sku"].matches.iter().map(|m| &text[m.start..m.end]).collect();
    assert_eq!(skus, ["0042", "1337"]);
    assert_eq!(out["email.v1"].matches[0].value, "ops@example.com");
}

#[test]
fn catastrophic_and_unsupported_features_are_rejected_at_admission() {
    for (pattern, expected) in [
        (r"(a+)\1", RegexError::Backreference),
        (r"foo(?=bar)", RegexError::Lookaround),
        (r"(?<!foo)bar", RegexError::Lookaround),
    ] {
        assert_eq!(
            CompiledPattern::compile(&RegexPatternSpec::custom("p", pattern, 0)).unwrap_err(),
            expected,
            "{pattern}"
        );
    }
}

#[test]
fn nested_quantifiers_cannot_cause_super_linear_work() {
    let compiled = CompiledPattern::compile(&RegexPatternSpec::custom("n", r"(x+x+)+y", 0)).unwrap();
    let hostile = "x".repeat(300_000);
    let started = std::time::Instant::now();
    let out = extract(&[compiled], &hostile).unwrap();
    assert!(out["n"].matches.is_empty());
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[test]
fn result_counts_are_bounded_and_flagged() {
    let compiled = CompiledPattern::compile(&RegexPatternSpec::builtin("number")).unwrap();
    let text = "1 ".repeat(MAX_MATCHES_PER_PATTERN * 2);
    let out = extract(&[compiled], &text).unwrap();
    assert_eq!(out["number.v1"].matches.len(), MAX_MATCHES_PER_PATTERN);
    assert!(out["number.v1"].truncated);
}

#[test]
fn custom_fields_share_the_admission_gate() {
    let spec = |pattern: &str| CustomFieldSpec {
        name: "f".into(),
        regex: vec![pattern.into()],
        part: Part::Body,
        group: 0,
    };
    assert!(matches!(
        CustomField::compile(&spec(r"(a)\1")),
        Err(CustomFieldError::UnsupportedPattern {
            construct: "backreference",
            ..
        })
    ));
    assert!(matches!(
        CustomField::compile(&spec(r"a(?!b)")),
        Err(CustomFieldError::UnsupportedPattern {
            construct: "look-around",
            ..
        })
    ));
    assert!(matches!(
        CustomField::compile(&spec("(")),
        Err(CustomFieldError::InvalidPattern { .. })
    ));
    assert!(CustomField::compile(&spec(r"(a+)+$")).is_ok());
}
