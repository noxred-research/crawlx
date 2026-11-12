//! Authored contracts of the regex-delimited and UAX 29 sentence chunkers; no model or network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::extraction::{
    ChunkPatternV1, ExtractionPolicyV1, RegexAdmissionError, WordChunkEnvelopeV1, WordChunkErrorV1,
    WordChunkPolicyV1, WordChunkStrategyV1,
};

fn regex_policy(pattern: &str) -> WordChunkPolicyV1 {
    let mut policy = WordChunkPolicyV1::default();
    policy.strategy = WordChunkStrategyV1::Regex {
        pattern: ChunkPatternV1::new(pattern).unwrap(),
    };
    policy
}
fn sentence_policy(window: usize) -> WordChunkPolicyV1 {
    let mut policy = WordChunkPolicyV1::default();
    policy.strategy = WordChunkStrategyV1::Sentences { window };
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
fn regex_chunks_split_on_delimiters_trim_whitespace_and_drop_empty_spans() {
    let text = "\n\nFirst paragraph\nstill first.\n\n\n  Second one.  \n\n\u{3000}Third \u{1F642} end\n\n";
    let policy = regex_policy(r"\n\s*\n");
    let chunks = WordChunkEnvelopeV1::build(text, policy).unwrap();
    assert_eq!(
        slices(text, &chunks),
        [
            "First paragraph\nstill first.",
            "Second one.",
            "Third \u{1F642} end"
        ]
    );
    assert_eq!(chunks.implementation, "native_regex_delimited_spans_v1");
    chunks.validate(text, &policy).unwrap();
    assert_eq!(chunks, WordChunkEnvelopeV1::build(text, policy).unwrap());
    // Every range is a half-open, ordered, UTF-8-aligned slice of the exact input.
    assert!(chunks.ranges.windows(2).all(|pair| pair[0].end <= pair[1].start));
    assert!(chunks
        .ranges
        .iter()
        .all(|r| text.is_char_boundary(r.start) && text.is_char_boundary(r.end)));
}

#[test]
fn regex_chunks_ignore_empty_matches_and_handle_text_without_delimiters() {
    // `x*` matches the empty string everywhere: no delimiter, the whole text is one span.
    let text = "alpha beta\u{a0}gamma";
    let chunks = WordChunkEnvelopeV1::build(text, regex_policy("x*")).unwrap();
    assert_eq!(slices(text, &chunks), [text]);
    // Empty and whitespace-only text have no spans.
    for blank in ["", "  \n\t\u{2003}"] {
        let chunks = WordChunkEnvelopeV1::build(blank, regex_policy(r"\n")).unwrap();
        assert!(chunks.ranges.is_empty());
        chunks.validate(blank, &regex_policy(r"\n")).unwrap();
    }
    // A text that is only delimiters has no spans either.
    let chunks = WordChunkEnvelopeV1::build("\n\n\n", regex_policy(r"\n")).unwrap();
    assert!(chunks.ranges.is_empty());
}

#[test]
fn regex_chunks_never_split_a_scalar_whatever_the_pattern_matches() {
    let text = "日本語。中文。한국어。🙂🙂end";
    let chunks = WordChunkEnvelopeV1::build(text, regex_policy("。|🙂")).unwrap();
    assert_eq!(slices(text, &chunks), ["日本語", "中文", "한국어", "end"]);
    // A byte-level class cannot split a scalar: the pattern is matched on scalars, not bytes.
    let text = "a\u{e9}b\u{e9}c";
    let chunks = WordChunkEnvelopeV1::build(text, regex_policy(r"\x{e9}")).unwrap();
    assert_eq!(slices(text, &chunks), ["a", "b", "c"]);
}

#[test]
fn catastrophic_and_backtracking_patterns_are_rejected_at_admission() {
    for (pattern, expected) in [
        (r"(a)\1", RegexAdmissionError::Backreference),
        (r"foo(?=bar)", RegexAdmissionError::Lookaround),
        (r"(?<!x)y", RegexAdmissionError::Lookaround),
    ] {
        assert_eq!(
            regex_policy(pattern).validate(),
            Err(WordChunkErrorV1::Pattern(expected)),
            "{pattern}"
        );
        assert!(matches!(
            WordChunkEnvelopeV1::build("text", regex_policy(pattern)),
            Err(WordChunkErrorV1::Pattern(_))
        ));
    }
    // Too deeply nested, too large once compiled and syntactically invalid patterns fail typed.
    let deep = format!("{}a{}", "(".repeat(100), ")".repeat(100));
    assert_eq!(
        regex_policy(&deep).validate(),
        Err(WordChunkErrorV1::Pattern(RegexAdmissionError::TooComplex))
    );
    let huge = r"\pL{1000}\pL{1000}";
    assert!(matches!(
        regex_policy(huge).validate(),
        Err(WordChunkErrorV1::Pattern(RegexAdmissionError::TooComplex))
    ));
    assert!(matches!(
        regex_policy("(").validate(),
        Err(WordChunkErrorV1::Pattern(RegexAdmissionError::Syntax(_)))
    ));
    // The classic exponential pattern is accepted only because the engine cannot backtrack:
    // matching a hostile input completes in linear time and returns promptly.
    let hostile = format!("{}!", "a".repeat(50_000));
    let started = std::time::Instant::now();
    let chunks = WordChunkEnvelopeV1::build(&hostile, regex_policy(r"(a+)+$")).unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(chunks.ranges.len() <= 1);
    // Length is bounded when the pattern value is made.
    assert_eq!(ChunkPatternV1::new(""), Err(RegexAdmissionError::Empty));
    assert!(matches!(
        ChunkPatternV1::new(&"a".repeat(513)),
        Err(RegexAdmissionError::TooLong { len: 513 })
    ));
    assert!(ChunkPatternV1::new(&"a".repeat(512)).is_ok());
}

#[test]
fn sentence_chunks_follow_uax29_across_scripts_and_group_by_window() {
    let text =
        "Dr. Rowan arrived at 3.30 p.m. today.  Was the gate open?  Yes!\u{2003}日本語の文です。二つ目の文。";
    let one = WordChunkEnvelopeV1::build(text, sentence_policy(1)).unwrap();
    assert_eq!(one.implementation, "native_uax29_sentence_groups_v1");
    let found = slices(text, &one);
    // Whole text is covered by whitespace-trimmed sentences in order, nothing duplicated.
    assert!(found.contains(&"Was the gate open?"));
    assert!(found.contains(&"Yes!"));
    assert!(found.contains(&"日本語の文です。"));
    assert!(found.contains(&"二つ目の文。"));
    assert!(one.ranges.windows(2).all(|pair| pair[0].end <= pair[1].start));
    let two = WordChunkEnvelopeV1::build(text, sentence_policy(2)).unwrap();
    assert_eq!(two.ranges.len(), one.ranges.len().div_ceil(2));
    // The first grouped range spans the first two sentences including the whitespace between.
    assert_eq!(two.ranges[0].start, one.ranges[0].start);
    assert_eq!(two.ranges[0].end, one.ranges[1].end);
    // The last grouped range may be short.
    let last_single = one.ranges.last().unwrap();
    assert_eq!(two.ranges.last().unwrap().end, last_single.end);
    two.validate(text, &sentence_policy(2)).unwrap();
    assert_eq!(one, WordChunkEnvelopeV1::build(text, sentence_policy(1)).unwrap());
}

#[test]
fn sentence_chunks_are_utf8_safe_for_combining_marks_emoji_and_crlf() {
    let text = "Cafe\u{301} ouvert.\r\nL\u{e9}a dit oui!\u{1F44D}\u{1F3FD} Fin";
    let chunks = WordChunkEnvelopeV1::build(text, sentence_policy(1)).unwrap();
    assert!(!chunks.ranges.is_empty());
    for range in &chunks.ranges {
        assert!(text.is_char_boundary(range.start) && text.is_char_boundary(range.end));
        let slice = &text[range.start..range.end];
        assert_eq!(slice, slice.trim());
    }
    for blank in ["", " \r\n\t "] {
        assert!(WordChunkEnvelopeV1::build(blank, sentence_policy(1))
            .unwrap()
            .ranges
            .is_empty());
    }
}

#[test]
fn chunkers_fail_closed_one_over_every_inclusive_cap() {
    let text = "One. Two. Three. Four. Five.";
    let mut policy = sentence_policy(1);
    policy.max_ranges = 5;
    assert_eq!(WordChunkEnvelopeV1::build(text, policy).unwrap().ranges.len(), 5);
    policy.max_ranges = 4;
    assert_eq!(
        WordChunkEnvelopeV1::build(text, policy),
        Err(WordChunkErrorV1::Limit("result ranges"))
    );
    let mut policy = sentence_policy(1);
    policy.max_words = 4;
    assert_eq!(
        WordChunkEnvelopeV1::build(text, policy),
        Err(WordChunkErrorV1::Limit("segments"))
    );
    let mut policy = regex_policy(r"\.");
    policy.max_words = 5;
    assert_eq!(WordChunkEnvelopeV1::build(text, policy).unwrap().ranges.len(), 5);
    policy.max_words = 4;
    assert_eq!(
        WordChunkEnvelopeV1::build(text, policy),
        Err(WordChunkErrorV1::Limit("segments"))
    );
    let mut policy = regex_policy(r"\.");
    policy.max_input_bytes = text.len();
    assert!(WordChunkEnvelopeV1::build(text, policy).is_ok());
    policy.max_input_bytes = text.len() - 1;
    assert_eq!(
        WordChunkEnvelopeV1::build(text, policy),
        Err(WordChunkErrorV1::Limit("input bytes"))
    );
    // The scalar ceiling counts scalars, not bytes.
    let wide = "日本語。日本語。";
    let mut policy = regex_policy("。");
    policy.max_scan_chars = wide.chars().count();
    assert!(WordChunkEnvelopeV1::build(wide, policy).is_ok());
    policy.max_scan_chars -= 1;
    assert_eq!(
        WordChunkEnvelopeV1::build(wide, policy),
        Err(WordChunkErrorV1::Limit("scanned scalars"))
    );
    let mut policy = sentence_policy(1);
    policy.max_scan_chars = wide.chars().count() - 1;
    assert_eq!(
        WordChunkEnvelopeV1::build(wide, policy),
        Err(WordChunkErrorV1::Limit("scanned scalars"))
    );
    assert_eq!(
        sentence_policy(0).validate(),
        Err(WordChunkErrorV1::InvalidPolicy)
    );
    assert_eq!(
        sentence_policy(1_000_001).validate(),
        Err(WordChunkErrorV1::InvalidPolicy)
    );
}

#[test]
fn chunk_envelopes_detect_tampering_and_strategy_substitution() {
    let text = "Alpha one.\n\nBeta two.\n\nGamma three.";
    let policy = regex_policy(r"\n\n");
    let good = WordChunkEnvelopeV1::build(text, policy).unwrap();
    good.validate(text, &policy).unwrap();
    // Stale text, edited ranges, another strategy's implementation id and another policy all fail.
    assert_eq!(
        good.validate("other", &policy),
        Err(WordChunkErrorV1::InvalidEnvelope)
    );
    let mut moved = good.clone();
    moved.ranges[1].end += 1;
    assert_eq!(
        moved.validate(text, &policy),
        Err(WordChunkErrorV1::InvalidEnvelope)
    );
    let mut renamed = good.clone();
    renamed.implementation = "native_uax29_sentence_groups_v1".into();
    assert_eq!(
        renamed.validate(text, &policy),
        Err(WordChunkErrorV1::InvalidEnvelope)
    );
    assert_eq!(
        good.validate(text, &regex_policy(r"\n")),
        Err(WordChunkErrorV1::InvalidEnvelope)
    );
    assert_eq!(
        good.validate(text, &sentence_policy(1)),
        Err(WordChunkErrorV1::InvalidEnvelope)
    );
}

#[test]
fn chunk_policy_wire_format_round_trips_and_rejects_unknown_or_oversize_patterns() {
    let json = serde_json::json!({ "strategy": { "kind": "regex", "pattern": "\\n\\n" } });
    let policy: WordChunkPolicyV1 = serde_json::from_value(json).unwrap();
    assert_eq!(
        serde_json::from_str::<WordChunkPolicyV1>(&serde_json::to_string(&policy).unwrap()).unwrap(),
        policy
    );
    assert_eq!(
        serde_json::to_value(policy.strategy).unwrap(),
        serde_json::json!({ "kind": "regex", "pattern": "\\n\\n" })
    );
    let sentences: WordChunkPolicyV1 =
        serde_json::from_value(serde_json::json!({ "strategy": { "kind": "sentences", "window": 3 } }))
            .unwrap();
    assert_eq!(sentences.strategy, WordChunkStrategyV1::Sentences { window: 3 });
    for bad in [
        serde_json::json!({ "strategy": { "kind": "regex" } }),
        serde_json::json!({ "strategy": { "kind": "regex", "pattern": "a".repeat(513) } }),
        serde_json::json!({ "strategy": { "kind": "regex", "pattern": "x", "flags": "i" } }),
        serde_json::json!({ "strategy": { "kind": "sentences" } }),
        serde_json::json!({ "strategy": { "kind": "paragraphs" } }),
    ] {
        assert!(serde_json::from_value::<WordChunkPolicyV1>(bad).is_err());
    }
}

#[test]
fn a_catastrophic_pattern_is_refused_by_extraction_policy_admission() {
    let mut chunks = WordChunkPolicyV1::default();
    chunks.strategy = WordChunkStrategyV1::Regex {
        pattern: ChunkPatternV1::new(r"(.)\1+").unwrap(),
    };
    let mut policy = ExtractionPolicyV1::default();
    policy.chunks = Some(chunks);
    assert!(policy.validate().is_err());
    let mut ok = ExtractionPolicyV1::default();
    ok.chunks = Some(regex_policy(r"\n\n"));
    ok.validate().unwrap();
    // Omission preserves the existing policy identity.
    let plain = serde_json::to_value(ExtractionPolicyV1::default()).unwrap();
    assert!(plain.get("chunks").is_none());
}
