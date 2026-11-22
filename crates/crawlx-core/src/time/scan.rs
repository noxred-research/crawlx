//! Scanning primitives shared by the RFC 3339, RFC 2822 and fixed-format parsers.
//!
//! The grammar they implement is the one the former `chrono` based parsers accepted: leading
//! white space before numbers, at most `max` digits per number, three-letter month and weekday
//! names in any case, and the RFC 2822 legacy zone names. Keeping it identical keeps every
//! stored or received date text parsing exactly as before.

use super::error::{ParseResult, INVALID, OUT_OF_RANGE, TOO_SHORT};
use time::Weekday;

/// Read `min..=max` ASCII digits as a non-negative number. Digits past `max` stay in the rest.
pub(super) fn number(s: &str, min: usize, max: usize) -> ParseResult<(&str, i64)> {
    let bytes = s.as_bytes();
    if bytes.len() < min {
        return Err(TOO_SHORT);
    }
    let mut n = 0i64;
    for (i, &c) in bytes.iter().take(max).enumerate() {
        if !c.is_ascii_digit() {
            return if i < min { Err(INVALID) } else { Ok((&s[i..], n)) };
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(i64::from(c - b'0')))
            .ok_or(OUT_OF_RANGE)?;
    }
    Ok((&s[max.min(bytes.len())..], n))
}

/// Read a signed year: an explicit sign allows any number of digits, no sign allows four.
pub(super) fn year(s: &str) -> ParseResult<(&str, i64)> {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('-') {
        let (rest, v) = number(rest, 1, usize::MAX)?;
        Ok((rest, 0i64.checked_sub(v).ok_or(OUT_OF_RANGE)?))
    } else if let Some(rest) = s.strip_prefix('+') {
        number(rest, 1, usize::MAX)
    } else {
        number(s, 1, 4)
    }
}

/// Read a number of `min..=max` digits after optional leading white space.
pub(super) fn field(s: &str, max: usize) -> ParseResult<(&str, i64)> {
    number(s.trim_start(), 1, max)
}

/// Read a fraction of a second (one or more digits after the dot) as nanoseconds. Digits past
/// the ninth are skipped.
pub(super) fn nanosecond(s: &str) -> ParseResult<(&str, u32)> {
    const SCALE: [u32; 10] = [0, 100_000_000, 10_000_000, 1_000_000, 100_000, 10_000, 1_000, 100, 10, 1];
    let original = s.len();
    let (rest, v) = number(s, 1, 9)?;
    let consumed = original - rest.len();
    let v = u32::try_from(v).map_err(|_| OUT_OF_RANGE)?;
    let v = v.checked_mul(SCALE[consumed]).ok_or(OUT_OF_RANGE)?;
    Ok((rest.trim_start_matches(|c: char| c.is_ascii_digit()), v))
}

/// Month index 0 to 11 from the first three letters.
pub(super) fn short_month0(s: &str) -> ParseResult<(&str, u8)> {
    let b = s.as_bytes();
    if b.len() < 3 {
        return Err(TOO_SHORT);
    }
    let month0 = match (b[0] | 32, b[1] | 32, b[2] | 32) {
        (b'j', b'a', b'n') => 0,
        (b'f', b'e', b'b') => 1,
        (b'm', b'a', b'r') => 2,
        (b'a', b'p', b'r') => 3,
        (b'm', b'a', b'y') => 4,
        (b'j', b'u', b'n') => 5,
        (b'j', b'u', b'l') => 6,
        (b'a', b'u', b'g') => 7,
        (b's', b'e', b'p') => 8,
        (b'o', b'c', b't') => 9,
        (b'n', b'o', b'v') => 10,
        (b'd', b'e', b'c') => 11,
        _ => return Err(INVALID),
    };
    Ok((&s[3..], month0))
}

/// Weekday from the first three letters.
pub(super) fn short_weekday(s: &str) -> ParseResult<(&str, Weekday)> {
    let b = s.as_bytes();
    if b.len() < 3 {
        return Err(TOO_SHORT);
    }
    let weekday = match (b[0] | 32, b[1] | 32, b[2] | 32) {
        (b'm', b'o', b'n') => Weekday::Monday,
        (b't', b'u', b'e') => Weekday::Tuesday,
        (b'w', b'e', b'd') => Weekday::Wednesday,
        (b't', b'h', b'u') => Weekday::Thursday,
        (b'f', b'r', b'i') => Weekday::Friday,
        (b's', b'a', b't') => Weekday::Saturday,
        (b's', b'u', b'n') => Weekday::Sunday,
        _ => return Err(INVALID),
    };
    Ok((&s[3..], weekday))
}

/// Consume exactly the byte `c`.
pub(super) fn char(s: &str, c: u8) -> ParseResult<&str> {
    match s.as_bytes().first() {
        Some(&b) if b == c => Ok(&s[1..]),
        Some(_) => Err(INVALID),
        None => Err(TOO_SHORT),
    }
}

/// Consume one or more white space characters.
pub(super) fn space(s: &str) -> ParseResult<&str> {
    let trimmed = s.trim_start();
    if trimmed.len() < s.len() {
        Ok(trimmed)
    } else if s.is_empty() {
        Err(TOO_SHORT)
    } else {
        Err(INVALID)
    }
}

/// Consume any number (including none) of colons and white space.
pub(super) fn colon_or_space(s: &str) -> ParseResult<&str> {
    Ok(s.trim_start_matches(|c: char| c == ':' || c.is_whitespace()))
}

/// How the hour and minute of a numeric offset are separated.
#[derive(Clone, Copy)]
pub(super) enum Colon {
    /// Exactly one colon.
    Required,
    /// No separator.
    Absent,
    /// Any number of colons and white space.
    Loose,
}

/// A numeric offset (`+hh:mm`, `Z`) in seconds.
pub(super) fn timezone_offset(
    s: &str,
    colon: Colon,
    allow_zulu: bool,
    allow_unicode_minus: bool,
) -> ParseResult<(&str, i32)> {
    if allow_zulu {
        if let Some(b'Z' | b'z') = s.as_bytes().first() {
            return Ok((&s[1..], 0));
        }
    }
    let (negative, mut s) = match s.chars().next() {
        Some('+') => (false, &s[1..]),
        Some('-') => (true, &s[1..]),
        Some('\u{2212}') => {
            if !allow_unicode_minus {
                return Err(INVALID);
            }
            (true, &s['\u{2212}'.len_utf8()..])
        }
        Some(_) => return Err(INVALID),
        None => return Err(TOO_SHORT),
    };
    let digits = |s: &str| -> ParseResult<(u8, u8)> {
        let b = s.as_bytes();
        if b.len() < 2 {
            Err(TOO_SHORT)
        } else {
            Ok((b[0], b[1]))
        }
    };
    let hours = match digits(s)? {
        (h1 @ b'0'..=b'9', h2 @ b'0'..=b'9') => i32::from((h1 - b'0') * 10 + (h2 - b'0')),
        _ => return Err(INVALID),
    };
    s = &s[2..];
    s = match colon {
        Colon::Required => char(s, b':')?,
        Colon::Absent => s,
        Colon::Loose => colon_or_space(s)?,
    };
    let minutes = match digits(s)? {
        (m1 @ b'0'..=b'5', m2 @ b'0'..=b'9') => i32::from((m1 - b'0') * 10 + (m2 - b'0')),
        (b'6'..=b'9', b'0'..=b'9') => return Err(OUT_OF_RANGE),
        _ => return Err(INVALID),
    };
    s = &s[2..];
    let seconds = hours * 3600 + minutes * 60;
    Ok((s, if negative { -seconds } else { seconds }))
}

/// An RFC 2822 zone: `+hhmm`, `-hhmm`, `UT`, `GMT`, the North American names, or a military
/// letter (read as `-0000`).
pub(super) fn timezone_offset_2822(s: &str) -> ParseResult<(&str, i32)> {
    let upto = s.as_bytes().iter().position(|c| !c.is_ascii_alphabetic()).unwrap_or(s.len());
    if upto == 0 {
        return timezone_offset(s, Colon::Absent, false, false);
    }
    let name = &s.as_bytes()[..upto];
    let rest = &s[upto..];
    let hours = |h: i32| Ok((rest, h * 3600));
    if name.eq_ignore_ascii_case(b"gmt") || name.eq_ignore_ascii_case(b"ut") || name.eq_ignore_ascii_case(b"z") {
        return hours(0);
    } else if name.eq_ignore_ascii_case(b"edt") {
        return hours(-4);
    } else if name.eq_ignore_ascii_case(b"est") || name.eq_ignore_ascii_case(b"cdt") {
        return hours(-5);
    } else if name.eq_ignore_ascii_case(b"cst") || name.eq_ignore_ascii_case(b"mdt") {
        return hours(-6);
    } else if name.eq_ignore_ascii_case(b"mst") || name.eq_ignore_ascii_case(b"pdt") {
        return hours(-7);
    } else if name.eq_ignore_ascii_case(b"pst") {
        return hours(-8);
    } else if name.len() == 1 {
        if let b'a'..=b'i' | b'k'..=b'y' | b'A'..=b'I' | b'K'..=b'Y' = name[0] {
            return Ok((rest, 0));
        }
    }
    Err(INVALID)
}

/// Consume an RFC 2822 comment, including the white space before it.
pub(super) fn comment_2822(s: &str) -> ParseResult<&str> {
    enum State {
        Start,
        Next(usize),
        Escape(usize),
    }
    let s = s.trim_start();
    let mut state = State::Start;
    for (i, c) in s.bytes().enumerate() {
        state = match (state, c) {
            (State::Start, b'(') => State::Next(1),
            (State::Next(1), b')') => return Ok(&s[i + 1..]),
            (State::Next(depth), b'\\') => State::Escape(depth),
            (State::Next(depth), b'(') => State::Next(depth + 1),
            (State::Next(depth), b')') => State::Next(depth - 1),
            (State::Next(depth) | State::Escape(depth), _) => State::Next(depth),
            _ => return Err(INVALID),
        };
    }
    Err(TOO_SHORT)
}
