//! Authored native word-window contracts; no upstream code, model or network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::extraction::{
    ExtractionPolicyV1, WordChunkEnvelopeV1, WordChunkErrorV1, WordChunkPolicyV1, WordChunkStrategyV1,
};

fn policy(strategy: WordChunkStrategyV1) -> WordChunkPolicyV1 {
    let mut policy = WordChunkPolicyV1::default();
    policy.strategy = strategy;
    policy
}
fn slices<'a>(text: &'a str, chunks: &WordChunkEnvelopeV1) -> Vec<&'a str> {
    chunks
        .ranges
        .iter()
        .map(|range| &text[range.start..range.end])
        .collect()
}

#[test]
fn native_word_chunks_preserve_unicode_and_preformatted_internal_whitespace() {
    let text = "\tα\u{2003}beta\n  中🙂  delta\tend  ";
    let configured = policy(WordChunkStrategyV1::Fixed { window: 2 });
    let chunks = WordChunkEnvelopeV1::build(text, configured).unwrap();
    assert_eq!(slices(text, &chunks), ["α\u{2003}beta", "中🙂  delta", "end"]);
    assert_eq!(chunks, WordChunkEnvelopeV1::build(text, configured).unwrap());
    chunks.validate(text, &configured).unwrap();
    assert!(chunks.ranges.windows(2).all(|pair| pair[0].end <= pair[1].start));
    // Combining marks, punctuation and zero-width space remain inside native words.
    let text = "e\u{301},x\u{200b}y\u{a0}z";
    let chunks = WordChunkEnvelopeV1::build(text, policy(WordChunkStrategyV1::Fixed { window: 1 })).unwrap();
    assert_eq!(slices(text, &chunks), ["e\u{301},x\u{200b}y", "z"]);
}

#[test]
fn native_word_chunks_sliding_full_tail_differs_from_overlap_short_tail() {
    let text = "a b c d e f g h";
    for (strategy, expected) in [
        (
            WordChunkStrategyV1::Fixed { window: 3 },
            vec!["a b c", "d e f", "g h"],
        ),
        (
            WordChunkStrategyV1::Sliding { window: 3, step: 2 },
            vec!["a b c", "c d e", "e f g", "f g h"],
        ),
        (
            WordChunkStrategyV1::Overlapping {
                window: 3,
                overlap: 1,
            },
            vec!["a b c", "c d e", "e f g", "g h"],
        ),
        (
            WordChunkStrategyV1::Sliding { window: 2, step: 4 },
            vec!["a b", "e f", "g h"],
        ),
    ] {
        let policy = policy(strategy);
        let chunks = WordChunkEnvelopeV1::build(text, policy).unwrap();
        assert_eq!(slices(text, &chunks), expected);
        assert!(chunks.ranges.windows(2).all(|pair| pair[0].start < pair[1].start));
        chunks.validate(text, &policy).unwrap();
    }
    let text = "a b c d e f";
    let chunks =
        WordChunkEnvelopeV1::build(text, policy(WordChunkStrategyV1::Sliding { window: 3, step: 3 }))
            .unwrap();
    assert_eq!(slices(text, &chunks), ["a b c", "d e f"]);
    let text = "a b c d e";
    let chunks = WordChunkEnvelopeV1::build(
        text,
        policy(WordChunkStrategyV1::Overlapping {
            window: 3,
            overlap: 1,
        }),
    )
    .unwrap();
    assert_eq!(slices(text, &chunks), ["a b c", "c d e"]);
}

#[test]
fn native_word_chunks_short_empty_and_exact_window_contracts() {
    for text in ["", " \n\t", "\tα  beta\n", " a b c "] {
        for strategy in [
            WordChunkStrategyV1::Sliding { window: 3, step: 2 },
            WordChunkStrategyV1::Overlapping {
                window: 3,
                overlap: 1,
            },
        ] {
            let policy = policy(strategy);
            let chunks = WordChunkEnvelopeV1::build(text, policy).unwrap();
            assert_eq!(slices(text, &chunks), [text]);
            assert_eq!(chunks.ranges[0].start, 0);
            assert_eq!(chunks.ranges[0].end, text.len());
            chunks.validate(text, &policy).unwrap();
        }
    }
    for text in ["", " \n\t"] {
        assert!(
            WordChunkEnvelopeV1::build(text, policy(WordChunkStrategyV1::Fixed { window: 3 }))
                .unwrap()
                .ranges
                .is_empty()
        );
    }
    let text = " a b c ";
    let chunks =
        WordChunkEnvelopeV1::build(text, policy(WordChunkStrategyV1::Sliding { window: 3, step: 1 }))
            .unwrap();
    assert_eq!(slices(text, &chunks), [text]);
    let chunks = WordChunkEnvelopeV1::build(
        text,
        policy(WordChunkStrategyV1::Overlapping {
            window: 3,
            overlap: 1,
        }),
    )
    .unwrap();
    assert_eq!(slices(text, &chunks), [text]);
}

#[test]
fn native_word_chunks_reject_nonprogress_underflow_and_unrepresentable_limits() {
    for strategy in [
        WordChunkStrategyV1::Fixed { window: 0 },
        WordChunkStrategyV1::Sliding { window: 1, step: 0 },
        WordChunkStrategyV1::Overlapping {
            window: 2,
            overlap: 2,
        },
        WordChunkStrategyV1::Overlapping {
            window: 2,
            overlap: usize::MAX,
        },
        WordChunkStrategyV1::Sliding {
            window: usize::MAX,
            step: usize::MAX,
        },
    ] {
        assert_eq!(
            WordChunkEnvelopeV1::build("x", policy(strategy)),
            Err(WordChunkErrorV1::InvalidPolicy)
        );
    }
    let mut excessive = WordChunkPolicyV1::default();
    excessive.max_input_bytes = usize::MAX;
    assert_eq!(excessive.validate(), Err(WordChunkErrorV1::InvalidPolicy));
    assert!(
        serde_json::from_value::<WordChunkPolicyV1>(serde_json::json!({"strategy":{"kind":"punkt"}}))
            .is_err()
    );
}

#[test]
fn native_word_chunks_inclusive_caps_fail_one_over_without_partial_success() {
    for (field, text, accepted, refused, limit_name) in [
        ("maxInputBytes", "é x", 4, 3, "input bytes"),
        ("maxScanChars", "é x", 3, 2, "scanned scalars"),
        ("maxWords", "é x", 2, 1, "word boundaries"),
        ("maxRanges", "é x", 2, 1, "result ranges"),
    ] {
        let mut json = serde_json::to_value(policy(WordChunkStrategyV1::Fixed { window: 1 })).unwrap();
        json[field] = accepted.into();
        let accepted: WordChunkPolicyV1 = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            WordChunkEnvelopeV1::build(text, accepted).unwrap().ranges.len(),
            2
        );
        json[field] = refused.into();
        let refused: WordChunkPolicyV1 = serde_json::from_value(json).unwrap();
        assert_eq!(
            WordChunkEnvelopeV1::build(text, refused),
            Err(WordChunkErrorV1::Limit(limit_name))
        );
    }
    for field in ["maxInputBytes", "maxScanChars", "maxWords", "maxRanges"] {
        let mut json = serde_json::to_value(WordChunkPolicyV1::default()).unwrap();
        json[field] = 0.into();
        assert_eq!(
            serde_json::from_value::<WordChunkPolicyV1>(json)
                .unwrap()
                .validate(),
            Err(WordChunkErrorV1::InvalidPolicy)
        );
    }
    for (field, ceiling) in [
        ("maxInputBytes", 16_777_216),
        ("maxScanChars", 16_777_216),
        ("maxWords", 1_000_000),
        ("maxRanges", 20_000),
    ] {
        let mut json = serde_json::to_value(WordChunkPolicyV1::default()).unwrap();
        json[field] = ceiling.into();
        serde_json::from_value::<WordChunkPolicyV1>(json.clone())
            .unwrap()
            .validate()
            .unwrap();
        json[field] = (ceiling + 1).into();
        assert_eq!(
            serde_json::from_value::<WordChunkPolicyV1>(json)
                .unwrap()
                .validate(),
            Err(WordChunkErrorV1::InvalidPolicy)
        );
    }
    for strategy in [
        WordChunkStrategyV1::Sliding { window: 3, step: 2 },
        WordChunkStrategyV1::Overlapping {
            window: 3,
            overlap: 1,
        },
    ] {
        let mut limited = policy(strategy);
        limited.max_ranges = 3;
        assert_eq!(
            WordChunkEnvelopeV1::build("a b c d e f g h", limited),
            Err(WordChunkErrorV1::Limit("result ranges"))
        );
    }
}

#[test]
fn native_word_chunks_corrupt_digest_utf8_bounds_order_and_policy_fail_closed() {
    let text = "α beta gamma delta";
    let policy = policy(WordChunkStrategyV1::Sliding { window: 2, step: 1 });
    let chunks = WordChunkEnvelopeV1::build(text, policy).unwrap();
    for mutation in 0..8 {
        let mut corrupt = chunks.clone();
        match mutation {
            0 => corrupt.ranges[0].start = 1,
            1 => corrupt.ranges[0].end = text.len() + 1,
            2 => corrupt.ranges.swap(0, 1),
            3 => corrupt.ranges[0].end = corrupt.ranges[0].start,
            4 => corrupt.implementation = "unknown".into(),
            5 => corrupt.version = 2,
            6 => corrupt.final_text_digest = crawlx_core::hash::Digest::of("wrong", text.as_bytes()),
            7 => {
                corrupt.ranges.pop();
            }
            _ => unreachable!(),
        }
        assert!(corrupt.validate(text, &policy).is_err());
    }
    assert!(chunks.validate("α beta GAMMA delta", &policy).is_err());
    let mut changed = policy;
    changed.max_ranges -= 1;
    assert!(chunks.validate(text, &changed).is_err());
}

#[test]
fn native_word_chunks_omission_preserves_existing_policy_serialization_identity() {
    let policy = ExtractionPolicyV1::default();
    let before = serde_json::to_vec(&policy).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert!(json.get("chunks").is_none());
    json["chunks"] = serde_json::Value::Null;
    let restored: ExtractionPolicyV1 = serde_json::from_value(json).unwrap();
    assert_eq!(serde_json::to_vec(&restored).unwrap(), before);
}
