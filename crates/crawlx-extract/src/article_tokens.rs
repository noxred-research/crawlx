//! Offline word segmentation: the `unicode_rules_v1` rule and the ICU4X dictionary/UAX29 Unicode 17
//! boundaries.
//!
//! ICU data and algorithms retain Unicode-3.0 licensing through the dependency.
//! Dictionary mode deliberately avoids the ICU LSTM engine. Script support is not
//! a measured language-accuracy claim. Every emitted UTF-8 range slices the source.

use crawlx_core::extraction::SourceRangeV1;
use icu_segmenter::{GraphemeClusterSegmenter, WordSegmenter, WordSegmenterBorrowed};

/// Longest word, in bytes, that either tokenizer reports; longer runs are dropped.
const MAX_WORD_BYTES: usize = 128;

/// A Han or kana scalar: the `unicode_rules_v1` rule reports each one as a word of its own.
/// Punctuation inside those blocks (for example the katakana middle dot) is not a word.
fn is_cjk_word(c: char) -> bool {
    (('\u{3400}'..='\u{9fff}').contains(&c) || ('\u{3040}'..='\u{30ff}').contains(&c)) && c.is_alphanumeric()
}

/// Scripts written without spaces whose words the rules tokenizer takes from the ICU dictionary:
/// Thai, Lao, Myanmar and Khmer.
fn needs_dictionary(c: char) -> bool {
    matches!(c, '\u{0e00}'..='\u{0eff}' | '\u{1000}'..='\u{109f}' | '\u{1780}'..='\u{17ff}')
}

fn is_apostrophe(c: char) -> bool {
    matches!(c, '\'' | '\u{2019}')
}

/// Calls `word(start, end)` for every `unicode_rules_v1` word of `source`, in order, and stops
/// as soon as it returns `false`.
///
/// The rule works on extended grapheme clusters, so combining marks, vowel signs, virama, nukta,
/// tone marks and joiners stay in the word they modify. A cluster that begins with an
/// alphanumeric scalar continues the current word; an apostrophe (`'` or U+2019) between two
/// letters does too (contractions). A Han or kana scalar is a word of its own. A word of Thai,
/// Lao, Myanmar or Khmer script is cut into dictionary words by ICU's offline segmenter. Words
/// longer than 128 bytes are not reported.
pub(crate) fn rules_words(source: &str, mut word: impl FnMut(usize, usize) -> bool) {
    fn flush(
        source: &str,
        (start, end): (usize, usize),
        dictionary: bool,
        segmenter: &mut Option<WordSegmenterBorrowed<'static>>,
        word: &mut impl FnMut(usize, usize) -> bool,
    ) -> bool {
        if !dictionary {
            return end - start > MAX_WORD_BYTES || word(start, end);
        }
        let segmenter = segmenter.get_or_insert_with(|| WordSegmenter::new_dictionary(Default::default()));
        let mut previous = 0;
        for boundary in segmenter.segment_str(&source[start..end]) {
            let (from, to) = (previous, boundary);
            previous = boundary;
            if from == to || to - from > MAX_WORD_BYTES {
                continue;
            }
            if !word(start + from, start + to) {
                return false;
            }
        }
        true
    }

    let clusters = GraphemeClusterSegmenter::new();
    let mut dictionary_segmenter = None;
    let mut run: Option<(usize, usize)> = None;
    let mut run_dictionary = false;
    let mut run_ends_in_letter = false;
    let mut previous = 0;
    for end in clusters.segment_str(source) {
        let (start, cluster_end) = (previous, end);
        previous = end;
        let Some(first) = source[start..cluster_end].chars().next() else {
            continue;
        };
        let joins_contraction = is_apostrophe(first)
            && cluster_end - start == first.len_utf8()
            && run.is_some()
            && run_ends_in_letter
            && source[cluster_end..]
                .chars()
                .next()
                .is_some_and(|next| next.is_alphabetic() && !is_cjk_word(next));
        if (first.is_alphanumeric() && !is_cjk_word(first)) || joins_contraction {
            run = Some((run.map_or(start, |(begin, _)| begin), cluster_end));
            run_dictionary |= needs_dictionary(first);
            run_ends_in_letter = first.is_alphabetic();
            continue;
        }
        if let Some(bounds) = run.take() {
            let dictionary = std::mem::take(&mut run_dictionary);
            if !flush(source, bounds, dictionary, &mut dictionary_segmenter, &mut word) {
                return;
            }
        }
        if is_cjk_word(first) && !word(start, cluster_end) {
            return;
        }
    }
    if let Some(bounds) = run {
        flush(
            source,
            bounds,
            run_dictionary,
            &mut dictionary_segmenter,
            &mut word,
        );
    }
}

pub(crate) fn dictionary(source: &str) -> (Vec<(String, SourceRangeV1)>, bool) {
    let segmenter = WordSegmenter::new_dictionary(Default::default());
    let mut previous = 0;
    let mut output = Vec::new();
    let mut truncated = false;
    // ICU 2.3's V1 word-type status can describe a trailing Extend property rather
    // than the lexical base (for example an Indic vowel sign). Classify the whole
    // original segment, not that boundary status, without changing its boundaries.
    for end in segmenter.segment_str(source) {
        let start = previous;
        previous = end;
        if start == end || !source[start..end].chars().any(char::is_alphanumeric) {
            continue;
        }
        if end.saturating_sub(start) > MAX_WORD_BYTES {
            truncated = true;
            continue;
        }
        if output.len() == 100_000 {
            truncated = true;
            break;
        }
        output.push((source[start..end].to_lowercase(), SourceRangeV1::new(start, end)));
    }
    (output, truncated)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn dictionary_segments_thai_cjk_and_preserves_indic_marks() {
        // Authored short expressions. These annotations test segmentation, not detector quality.
        for (text, expected) in [
            ("ภาษาไทย", vec!["ภาษา", "ไทย"]),
            ("日本語", vec!["日本語"]),
            ("हिन्दी भाषा", vec!["हिन्दी", "भाषा"]),
            ("café cafe\u{301}", vec!["café", "cafe\u{301}"]),
        ] {
            let (tokens, truncated) = dictionary(text);
            assert!(!truncated);
            assert_eq!(
                tokens.iter().map(|(token, _)| token.as_str()).collect::<Vec<_>>(),
                expected
            );
            for (token, span) in tokens {
                assert_eq!(text[span.start..span.end].to_lowercase(), token);
            }
        }
        let (tokens, _) = dictionary("हिन्दी! cafe\u{301}, … 123");
        assert_eq!(
            tokens.iter().map(|(token, _)| token.as_str()).collect::<Vec<_>>(),
            ["हिन्दी", "cafe\u{301}", "123"]
        );
    }

    fn rules(text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        rules_words(text, |start, end| {
            out.push(&text[start..end]);
            true
        });
        out
    }

    #[test]
    fn rules_keep_combining_marks_inside_their_word() {
        assert_eq!(rules("cafe\u{301} café"), ["cafe\u{301}", "café"]);
        // Virama and conjuncts, nukta, anusvara and chandrabindu.
        assert_eq!(rules("क्रिकेट पढ़ते हैं खिलाड़ी"), ["क्रिकेट", "पढ़ते", "हैं", "खिलाड़ी"]);
        // A zero-width joiner stays inside the word; an orphan mark is not a word.
        assert_eq!(rules("क्\u{200d}ष \u{094d}"), ["क्\u{200d}ष"]);
    }

    #[test]
    fn rules_keep_a_contraction_apostrophe_between_letters_only() {
        assert_eq!(
            rules("don't we\u{2019}ll l'eau 'quoted' dogs' 5'10 ''x"),
            ["don't", "we\u{2019}ll", "l'eau", "quoted", "dogs", "5", "10", "x"]
        );
    }

    #[test]
    fn rules_take_thai_words_from_the_dictionary_and_cap_other_runs() {
        assert_eq!(
            rules("ปลาว่ายน้ำ แมวนอนบนเก้าอี้"),
            ["ปลา", "ว่าย", "น้ำ", "แมว", "นอน", "บน", "เก้าอี้"]
        );
        // The 128-byte cap applies to words, not to a whole unspaced Thai sentence.
        let long = "ปลาว่ายน้ำ".repeat(40);
        assert!(long.len() > MAX_WORD_BYTES);
        let words = rules(&long);
        assert!(words.len() >= 40 && words.iter().all(|word| word.len() <= MAX_WORD_BYTES));
        assert_eq!(words.concat(), long);
        let latin = "a".repeat(MAX_WORD_BYTES + 1);
        assert!(rules(&format!("{latin} b")).iter().eq(["b"].iter()));
    }

    #[test]
    fn rules_report_han_and_kana_scalars_but_not_their_punctuation() {
        assert_eq!(rules("コーヒー・紅茶"), ["コ", "ー", "ヒ", "ー", "紅", "茶"]);
        assert_eq!(rules("日本語 a1"), ["日", "本", "語", "a1"]);
    }

    #[test]
    fn rules_stop_when_the_callback_declines() {
        let mut seen = 0;
        rules_words("one two three", |_, _| {
            seen += 1;
            seen < 2
        });
        assert_eq!(seen, 2);
    }
}
