//! Offline ICU4X 2.3 dictionary/UAX29 Unicode 17 word boundaries.
//!
//! ICU data and algorithms retain Unicode-3.0 licensing through the dependency.
//! Dictionary mode deliberately avoids the ICU LSTM engine. Script support is not
//! a measured language-accuracy claim. Every emitted UTF-8 range slices the source.

use crawlx_core::extraction::SourceRangeV1;
use icu_segmenter::WordSegmenter;

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
        if end.saturating_sub(start) > 128 {
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
}
