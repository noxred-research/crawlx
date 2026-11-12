//! Admission gate for caller-supplied regular expressions.
//!
//! Every pattern runs on the linear-time `regex` engine. Patterns that need backtracking
//! (backreferences, look-around) are refused with a typed error before anything is compiled, and
//! pattern length, nesting depth, compiled-program size and capture-group count are bounded, so an
//! attacker-chosen pattern can neither spin the CPU nor reserve unbounded memory. This is the one
//! place that decides what a user pattern may be; the extractor's pattern table and the native
//! regex chunker both call it.

use regex::{Regex, RegexBuilder};

/// Longest pattern accepted, in bytes.
pub const MAX_REGEX_PATTERN_LEN: usize = 512;
/// Most capture groups (including the whole match) in one pattern.
pub const MAX_REGEX_CAPTURE_GROUPS: usize = 33;
/// Compiled-program size limit per pattern, in bytes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Deepest group nesting accepted.
const REGEX_NEST_LIMIT: u32 = 64;

/// Why a pattern was not admitted.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegexAdmissionError {
    /// The pattern is empty.
    #[error("pattern is empty")]
    Empty,
    /// The pattern is longer than [`MAX_REGEX_PATTERN_LEN`].
    #[error("pattern length {len} exceeds {MAX_REGEX_PATTERN_LEN} bytes")]
    TooLong {
        /// Pattern length in bytes.
        len: usize,
    },
    /// The pattern uses a backreference, which the linear-time engine cannot evaluate.
    #[error("backreferences are not supported")]
    Backreference,
    /// The pattern uses look-ahead or look-behind, which the linear-time engine cannot evaluate.
    #[error("look-around assertions are not supported")]
    Lookaround,
    /// The pattern is not valid regex syntax.
    #[error("invalid pattern: {0}")]
    Syntax(String),
    /// The pattern nests too deeply, has too many capture groups or compiles above the size limit.
    #[error("pattern exceeds the nesting, capture-group or compiled-size limit")]
    TooComplex,
}

/// Check only what needs no compilation: emptiness and length.
///
/// # Errors
/// [`RegexAdmissionError::Empty`] or [`RegexAdmissionError::TooLong`].
pub const fn check_pattern_len(pattern: &str) -> Result<(), RegexAdmissionError> {
    if pattern.is_empty() {
        return Err(RegexAdmissionError::Empty);
    }
    if pattern.len() > MAX_REGEX_PATTERN_LEN {
        return Err(RegexAdmissionError::TooLong { len: pattern.len() });
    }
    Ok(())
}

/// Admit and compile one pattern for the linear-time engine.
///
/// # Errors
/// [`RegexAdmissionError::Empty`], [`RegexAdmissionError::TooLong`],
/// [`RegexAdmissionError::Backreference`], [`RegexAdmissionError::Lookaround`],
/// [`RegexAdmissionError::Syntax`] or [`RegexAdmissionError::TooComplex`].
pub fn admit_regex(pattern: &str) -> Result<Regex, RegexAdmissionError> {
    use regex_syntax::ast::{parse::ParserBuilder, ErrorKind};
    check_pattern_len(pattern)?;
    if let Err(error) = ParserBuilder::new()
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .parse(pattern)
    {
        return Err(match error.kind() {
            ErrorKind::UnsupportedBackreference => RegexAdmissionError::Backreference,
            ErrorKind::UnsupportedLookAround => RegexAdmissionError::Lookaround,
            ErrorKind::NestLimitExceeded(_) => RegexAdmissionError::TooComplex,
            other => RegexAdmissionError::Syntax(other.to_string()),
        });
    }
    let regex = RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|error| match error {
            regex::Error::CompiledTooBig(_) => RegexAdmissionError::TooComplex,
            other => RegexAdmissionError::Syntax(other.to_string()),
        })?;
    if regex.captures_len() > MAX_REGEX_CAPTURE_GROUPS {
        return Err(RegexAdmissionError::TooComplex);
    }
    Ok(regex)
}
