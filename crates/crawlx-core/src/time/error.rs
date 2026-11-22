//! Parse and range errors of the time facade.

use std::fmt;

/// Why a date or time text was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// A component is outside its valid range (month 13, hour 25, an offset of a day or more).
    OutOfRange,
    /// The components do not form a real instant (day 31 of April, a wrong weekday).
    Impossible,
    /// A required component is missing.
    NotEnough,
    /// The text does not follow the grammar.
    Invalid,
    /// The text ends before the grammar does.
    TooShort,
    /// The text continues after the grammar ends.
    TooLong,
}

/// A date or time text was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError(pub(crate) ParseErrorKind);

impl ParseError {
    /// Why the text was rejected.
    #[must_use]
    pub const fn kind(&self) -> ParseErrorKind {
        self.0
    }
}

pub(crate) const OUT_OF_RANGE: ParseError = ParseError(ParseErrorKind::OutOfRange);
pub(crate) const IMPOSSIBLE: ParseError = ParseError(ParseErrorKind::Impossible);
pub(crate) const NOT_ENOUGH: ParseError = ParseError(ParseErrorKind::NotEnough);
pub(crate) const INVALID: ParseError = ParseError(ParseErrorKind::Invalid);
pub(crate) const TOO_SHORT: ParseError = ParseError(ParseErrorKind::TooShort);
pub(crate) const TOO_LONG: ParseError = ParseError(ParseErrorKind::TooLong);

pub(crate) type ParseResult<T> = Result<T, ParseError>;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ParseErrorKind::OutOfRange => "input is out of range",
            ParseErrorKind::Impossible => "no possible date and time matching input",
            ParseErrorKind::NotEnough => "input is not enough for unique date and time",
            ParseErrorKind::Invalid => "input contains invalid characters",
            ParseErrorKind::TooShort => "premature end of input",
            ParseErrorKind::TooLong => "trailing input",
        })
    }
}

impl std::error::Error for ParseError {}

/// A duration does not fit the target type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfRangeError(pub(crate) ());

impl fmt::Display for OutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Source duration value is out of range for the target type")
    }
}

impl std::error::Error for OutOfRangeError {}
