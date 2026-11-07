//! Native Unicode-whitespace word windows over finalized privacy-approved text.
//!
//! These ranges preserve internal whitespace. They do not claim Python splitting,
//! Punkt, regex capture, TextTiling, or model-backed tokenizer equivalence.
use super::SourceRangeV1;
use crate::hash::Digest;
use serde::{Deserialize, Serialize};

const IMPLEMENTATION: &str = "native_unicode_whitespace_word_windows_v1";
const MAX_BYTES: usize = 16_777_216;
const MAX_WORDS: usize = 1_000_000;
const MAX_RANGES: usize = 20_000;

/// Native word-window strategy. Words are maximal runs of non-Unicode-whitespace scalars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum WordChunkStrategyV1 {
    /// Disjoint groups, including a short final group; empty input has no groups.
    Fixed {
        /// Positive number of words per group, at most one million.
        window: usize,
    },
    /// Full windows at each step, then the last full window if stepping leaves a tail.
    Sliding {
        /// Positive number of words per window, at most one million.
        window: usize,
        /// Positive advance in words, at most one million; gaps are allowed.
        step: usize,
    },
    /// Advance by window minus overlap, emitting a short final window.
    Overlapping {
        /// Positive number of words per window, at most one million.
        window: usize,
        /// Number of shared words; must be strictly smaller than window.
        overlap: usize,
    },
}
impl Default for WordChunkStrategyV1 {
    fn default() -> Self {
        Self::Fixed { window: 500 }
    }
}

/// Optional versioned word-window policy. Every limit is inclusive; one over fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct WordChunkPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Native fixed, sliding, or overlapping word windows.
    pub strategy: WordChunkStrategyV1,
    /// Final text byte ceiling, at most 16 MiB, checked before scanning or hashing.
    pub max_input_bytes: usize,
    /// Unicode scalar scan ceiling, at most 16,777,216; each input scalar is visited once.
    pub max_scan_chars: usize,
    /// Retained word-boundary ceiling, at most one million.
    pub max_words: usize,
    /// Emitted source-range ceiling, at most 20,000.
    pub max_ranges: usize,
}
impl Default for WordChunkPolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            strategy: WordChunkStrategyV1::default(),
            max_input_bytes: MAX_BYTES,
            max_scan_chars: MAX_BYTES,
            max_words: MAX_WORDS,
            max_ranges: MAX_RANGES,
        }
    }
}
impl WordChunkPolicyV1 {
    /// Check version, positive windows/steps, strict overlap progress and hard ceilings.
    ///
    /// # Errors
    /// Returns `InvalidPolicy` for unsupported versions, nonprogress or excessive limits.
    pub fn validate(&self) -> Result<(), WordChunkErrorV1> {
        let (window, step) = self.window_step()?;
        if self.version != 1
            || !(1..=MAX_WORDS).contains(&window)
            || !(1..=MAX_WORDS).contains(&step)
            || !(1..=MAX_BYTES).contains(&self.max_input_bytes)
            || !(1..=MAX_BYTES).contains(&self.max_scan_chars)
            || !(1..=MAX_WORDS).contains(&self.max_words)
            || !(1..=MAX_RANGES).contains(&self.max_ranges)
        {
            return Err(WordChunkErrorV1::InvalidPolicy);
        }
        Ok(())
    }

    fn window_step(&self) -> Result<(usize, usize), WordChunkErrorV1> {
        match self.strategy {
            WordChunkStrategyV1::Fixed { window } => Ok((window, window)),
            WordChunkStrategyV1::Sliding { window, step } => Ok((window, step)),
            WordChunkStrategyV1::Overlapping { window, overlap } => window
                .checked_sub(overlap)
                .filter(|step| *step > 0)
                .map(|step| (window, step))
                .ok_or(WordChunkErrorV1::InvalidPolicy),
        }
    }
}

/// Source-only word chunks bound to exact finalized document text and effective policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct WordChunkEnvelopeV1 {
    /// Exactly one.
    pub version: u16,
    /// Pinned native segmentation/window implementation, not upstream equivalence.
    pub implementation: String,
    /// Complete effective chunk policy, including work and output ceilings.
    pub policy: WordChunkPolicyV1,
    /// Domain-separated digest of the exact final `Document.text` bytes.
    pub final_text_digest: Digest,
    /// Half-open UTF-8 byte ranges, in algorithm order. Overlap is legitimate.
    pub ranges: Vec<SourceRangeV1>,
}

/// Typed failures never return a partial set of chunk ranges.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WordChunkErrorV1 {
    /// Policy version, progress or hard bounds are invalid.
    #[error("invalid word chunk policy")]
    InvalidPolicy,
    /// A configured inclusive input, scanning, boundary or range cap was exceeded.
    #[error("word chunk limit exceeded: {0}")]
    Limit(&'static str),
    /// Checked index arithmetic could not represent the next window.
    #[error("word chunk arithmetic overflow")]
    Arithmetic,
    /// Persisted metadata no longer matches exact final text, implementation or policy.
    #[error("word chunk envelope does not match finalized text and policy")]
    InvalidEnvelope,
}

impl WordChunkEnvelopeV1 {
    /// Compute source-only windows after all privacy projections and text truncation.
    ///
    /// Sliding and overlapping inputs with at most `window` words return one
    /// range over the entire original final text, including whitespace and empty text.
    /// Other windows span first through last word and preserve only internal whitespace.
    ///
    /// # Errors
    /// Returns a typed failure for invalid policy, arithmetic overflow or any exceeded cap.
    pub fn build(text: &str, policy: WordChunkPolicyV1) -> Result<Self, WordChunkErrorV1> {
        let mut ranges = Vec::new();
        visit_ranges(text, &policy, |range| {
            ranges.push(range);
            Ok(())
        })?;
        Ok(Self {
            version: 1,
            implementation: IMPLEMENTATION.into(),
            policy,
            final_text_digest: text_digest(text),
            ranges,
        })
    }

    /// Validate implementation, exact effective policy, digest and every algorithmic range.
    ///
    /// This checks UTF-8 boundaries, bounds, ordered starts, legitimate overlap and
    /// tail semantics by recomputing boundaries without allocating copied chunk text.
    ///
    /// # Errors
    /// Returns a typed failure for corruption, policy mismatch or exceeded work limits.
    pub fn validate(&self, text: &str, policy: &WordChunkPolicyV1) -> Result<(), WordChunkErrorV1> {
        policy.validate()?;
        if self.version != 1
            || self.implementation != IMPLEMENTATION
            || self.policy != *policy
            || text.len() > policy.max_input_bytes
            || self.ranges.len() > policy.max_ranges
            || self.final_text_digest != text_digest(text)
        {
            return Err(WordChunkErrorV1::InvalidEnvelope);
        }
        let mut index = 0_usize;
        visit_ranges(text, policy, |expected| {
            if self.ranges.get(index) != Some(&expected) {
                return Err(WordChunkErrorV1::InvalidEnvelope);
            }
            index = index.checked_add(1).ok_or(WordChunkErrorV1::Arithmetic)?;
            Ok(())
        })?;
        if index != self.ranges.len() {
            return Err(WordChunkErrorV1::InvalidEnvelope);
        }
        Ok(())
    }
}

fn text_digest(text: &str) -> Digest {
    Digest::of("crawlx.extract.chunks.final_text.v1", text.as_bytes())
}

fn visit_words(
    text: &str,
    policy: &WordChunkPolicyV1,
    mut emit: impl FnMut(SourceRangeV1) -> Result<(), WordChunkErrorV1>,
) -> Result<(), WordChunkErrorV1> {
    let mut words = 0_usize;
    let mut emit = |start, end| {
        if words == policy.max_words {
            return Err(WordChunkErrorV1::Limit("word boundaries"));
        }
        words = words.checked_add(1).ok_or(WordChunkErrorV1::Arithmetic)?;
        emit(SourceRangeV1::new(start, end))
    };
    let mut start = None;
    let mut scanned = 0_usize;
    for (offset, ch) in text.char_indices() {
        scanned = scanned.checked_add(1).ok_or(WordChunkErrorV1::Arithmetic)?;
        if scanned > policy.max_scan_chars {
            return Err(WordChunkErrorV1::Limit("scanned scalars"));
        }
        if ch.is_whitespace() {
            if let Some(begin) = start.take() {
                emit(begin, offset)?;
            }
        } else if start.is_none() {
            start = Some(offset);
        }
    }
    if let Some(begin) = start {
        emit(begin, text.len())?;
    }
    Ok(())
}

fn visit_ranges(
    text: &str,
    policy: &WordChunkPolicyV1,
    mut emit: impl FnMut(SourceRangeV1) -> Result<(), WordChunkErrorV1>,
) -> Result<(), WordChunkErrorV1> {
    policy.validate()?;
    if text.len() > policy.max_input_bytes {
        return Err(WordChunkErrorV1::Limit("input bytes"));
    }
    let mut count = 0_usize;
    let mut emit = |range| {
        if count == policy.max_ranges {
            return Err(WordChunkErrorV1::Limit("result ranges"));
        }
        count = count.checked_add(1).ok_or(WordChunkErrorV1::Arithmetic)?;
        emit(range)
    };
    let (window, step) = policy.window_step()?;
    if matches!(policy.strategy, WordChunkStrategyV1::Fixed { .. }) {
        // Disjoint groups need only their first/last boundary, never a per-word buffer.
        let mut begin = 0_usize;
        let mut end = 0_usize;
        let mut in_group = 0_usize;
        visit_words(text, policy, |word| {
            if in_group == 0 {
                begin = word.start;
            }
            end = word.end;
            in_group = in_group.checked_add(1).ok_or(WordChunkErrorV1::Arithmetic)?;
            if in_group == window {
                emit(SourceRangeV1::new(begin, end))?;
                in_group = 0;
            }
            Ok(())
        })?;
        if in_group != 0 {
            emit(SourceRangeV1::new(begin, end))?;
        }
        return Ok(());
    }
    let mut words = Vec::new();
    visit_words(text, policy, |word| {
        words.push(word);
        Ok(())
    })?;
    if words.len() <= window {
        return emit(SourceRangeV1::new(0, text.len()));
    }
    let sliding = matches!(policy.strategy, WordChunkStrategyV1::Sliding { .. });
    let mut first = 0_usize;
    let mut last_end = 0_usize;
    while first < words.len() {
        let end = first.checked_add(window).ok_or(WordChunkErrorV1::Arithmetic)?;
        if sliding && end > words.len() {
            break;
        }
        let end = end.min(words.len());
        let last = end.checked_sub(1).ok_or(WordChunkErrorV1::Arithmetic)?;
        emit(SourceRangeV1::new(words[first].start, words[last].end))?;
        last_end = end;
        if end == words.len() {
            break;
        }
        first = first.checked_add(step).ok_or(WordChunkErrorV1::Arithmetic)?;
    }
    if sliding && last_end < words.len() {
        let first = words
            .len()
            .checked_sub(window)
            .ok_or(WordChunkErrorV1::Arithmetic)?;
        let last = words.len().checked_sub(1).ok_or(WordChunkErrorV1::Arithmetic)?;
        emit(SourceRangeV1::new(words[first].start, words[last].end))?;
    }
    Ok(())
}
