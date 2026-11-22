//! A point on the UTC time line, and an instant with the offset it was written in.

use super::civil::{write_date, write_time, NaiveDate, NaiveDateTime, Parsed};
use super::error::{ParseError, ParseResult, INVALID, IMPOSSIBLE, OUT_OF_RANGE, TOO_LONG, TOO_SHORT};
use super::scan::{self, Colon};
use super::Duration;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::str::FromStr;
use time::{Date, Month, PlainDateTime, Time, UtcDateTime};

/// How many fractional-second digits [`Timestamp::to_rfc3339_opts`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecondsFormat {
    /// No fraction.
    Secs,
    /// Three digits.
    Millis,
    /// Six digits.
    Micros,
    /// Nine digits.
    Nanos,
    /// None, three, six or nine digits: the fewest that hold the value.
    AutoSi,
}

fn write_offset(w: &mut impl fmt::Write, offset: i32, use_z: bool) -> fmt::Result {
    if offset == 0 && use_z {
        return w.write_str("Z");
    }
    let sign = if offset < 0 { '-' } else { '+' };
    let minutes = offset.unsigned_abs() / 60;
    write!(w, "{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

fn write_rfc3339(w: &mut impl fmt::Write, local: PlainDateTime, offset: i32, format: SecondsFormat, use_z: bool) -> fmt::Result {
    write_date(w, local.date())?;
    w.write_str("T")?;
    let time = local.time();
    write!(w, "{:02}:{:02}:{:02}", time.hour(), time.minute(), time.second())?;
    let nano = time.nanosecond();
    match format {
        SecondsFormat::Secs => {}
        SecondsFormat::Millis => write!(w, ".{:03}", nano / 1_000_000)?,
        SecondsFormat::Micros => write!(w, ".{:06}", nano / 1_000)?,
        SecondsFormat::Nanos => write!(w, ".{nano:09}")?,
        SecondsFormat::AutoSi => {
            if nano == 0 {
            } else if nano.is_multiple_of(1_000_000) {
                write!(w, ".{:03}", nano / 1_000_000)?;
            } else if nano.is_multiple_of(1_000) {
                write!(w, ".{:06}", nano / 1_000)?;
            } else {
                write!(w, ".{nano:09}")?;
            }
        }
    }
    write_offset(w, offset, use_z)
}

/// A point on the UTC time line with nanosecond resolution, from -262143-01-01 to
/// +262142-12-31. Serializes as an RFC 3339 string in UTC with `Z`, with a fraction of three,
/// six or nine digits only when the value has one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(UtcDateTime);

const fn bound(year: i32, month: Month, day: u8, time: Time) -> Timestamp {
    match Date::from_calendar_date(year, month, day) {
        Ok(date) => Timestamp(UtcDateTime::new(date, time)),
        Err(_) => Timestamp(UtcDateTime::UNIX_EPOCH),
    }
}

impl Timestamp {
    /// 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Self = Self(UtcDateTime::UNIX_EPOCH);
    /// The earliest supported instant, -262143-01-01T00:00:00Z.
    pub const MIN_UTC: Self = bound(-262_143, Month::January, 1, Time::MIDNIGHT);
    /// The latest supported instant, +262142-12-31T23:59:59.999999999Z.
    pub const MAX_UTC: Self = bound(262_142, Month::December, 31, Time::MAX);

    /// The current wall-clock time.
    #[must_use]
    pub fn now() -> Self {
        Self(UtcDateTime::now())
    }

    pub(super) const fn plain(self) -> PlainDateTime {
        self.0.date().with_time(self.0.time())
    }

    pub(super) fn from_plain(value: PlainDateTime) -> Self {
        Self(value.as_utc())
    }

    #[cfg(feature = "sqlx")]
    pub(super) const fn utc(self) -> UtcDateTime {
        self.0
    }

    #[cfg(feature = "sqlx")]
    pub(super) fn from_time(value: time::OffsetDateTime) -> Option<Self> {
        Some(Self(UtcDateTime::from(value))).and_then(Self::in_range)
    }

    fn in_range(self) -> Option<Self> {
        (self >= Self::MIN_UTC && self <= Self::MAX_UTC).then_some(self)
    }

    /// The instant `secs` seconds and `nsecs` nanoseconds after the epoch.
    #[must_use]
    pub fn from_timestamp(secs: i64, nsecs: u32) -> Option<Self> {
        if nsecs >= 1_000_000_000 {
            return None;
        }
        let nanos = i128::from(secs) * 1_000_000_000 + i128::from(nsecs);
        UtcDateTime::from_unix_timestamp_nanos(nanos).ok().map(Self).and_then(Self::in_range)
    }

    /// The instant `secs` whole seconds after the epoch.
    #[must_use]
    pub fn from_timestamp_secs(secs: i64) -> Option<Self> {
        Self::from_timestamp(secs, 0)
    }

    /// The instant `millis` milliseconds after the epoch.
    #[must_use]
    pub fn from_timestamp_millis(millis: i64) -> Option<Self> {
        let nanos = i128::from(millis) * 1_000_000;
        UtcDateTime::from_unix_timestamp_nanos(nanos).ok().map(Self).and_then(Self::in_range)
    }

    /// The instant `micros` microseconds after the epoch.
    #[must_use]
    pub fn from_timestamp_micros(micros: i64) -> Option<Self> {
        let nanos = i128::from(micros) * 1_000;
        UtcDateTime::from_unix_timestamp_nanos(nanos).ok().map(Self).and_then(Self::in_range)
    }

    /// The instant at a calendar date and time of day in UTC, `None` when it does not exist.
    #[must_use]
    pub fn from_ymd_hms(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<Self> {
        NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second).map(NaiveDateTime::and_utc)
    }

    /// Whole seconds since the epoch (floor).
    #[must_use]
    pub const fn timestamp(self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Whole milliseconds since the epoch (floor).
    #[must_use]
    pub fn timestamp_millis(self) -> i64 {
        i64::try_from(self.0.unix_timestamp_nanos().div_euclid(1_000_000)).unwrap_or(i64::MAX)
    }

    /// Whole microseconds since the epoch (floor).
    #[must_use]
    pub fn timestamp_micros(self) -> i64 {
        i64::try_from(self.0.unix_timestamp_nanos().div_euclid(1_000)).unwrap_or(i64::MAX)
    }

    /// Nanoseconds since the epoch, `None` outside 1677 to 2262.
    #[must_use]
    pub fn timestamp_nanos_opt(self) -> Option<i64> {
        i64::try_from(self.0.unix_timestamp_nanos()).ok()
    }

    /// The nanoseconds past the whole second.
    #[must_use]
    pub const fn timestamp_subsec_nanos(self) -> u32 {
        self.0.nanosecond()
    }

    /// The milliseconds past the whole second.
    #[must_use]
    pub const fn timestamp_subsec_millis(self) -> u32 {
        self.0.nanosecond() / 1_000_000
    }

    /// The microseconds past the whole second.
    #[must_use]
    pub const fn timestamp_subsec_micros(self) -> u32 {
        self.0.nanosecond() / 1_000
    }

    /// The UTC calendar date.
    #[must_use]
    pub const fn date_naive(self) -> NaiveDate {
        NaiveDate::from_date(self.0.date())
    }

    /// The UTC date and time of day.
    #[must_use]
    pub const fn naive_utc(self) -> NaiveDateTime {
        NaiveDateTime::from_plain(self.plain())
    }

    /// The UTC year.
    #[must_use]
    pub const fn year(self) -> i32 {
        self.0.year()
    }

    /// The UTC month, 1 to 12.
    #[must_use]
    pub fn month(self) -> u32 {
        self.date_naive().month()
    }

    /// The UTC day of the month, 1 to 31.
    #[must_use]
    pub fn day(self) -> u32 {
        self.date_naive().day()
    }

    /// The UTC hour, 0 to 23.
    #[must_use]
    pub fn hour(self) -> u32 {
        u32::from(self.0.hour())
    }

    /// The UTC minute, 0 to 59.
    #[must_use]
    pub fn minute(self) -> u32 {
        u32::from(self.0.minute())
    }

    /// The UTC second, 0 to 59.
    #[must_use]
    pub fn second(self) -> u32 {
        u32::from(self.0.second())
    }

    /// `self + rhs`, `None` when the result is outside the supported range.
    #[must_use]
    pub fn checked_add_signed(self, rhs: Duration) -> Option<Self> {
        self.0.checked_add(rhs.inner()).map(Self).and_then(Self::in_range)
    }

    /// `self - rhs`, `None` when the result is outside the supported range.
    #[must_use]
    pub fn checked_sub_signed(self, rhs: Duration) -> Option<Self> {
        self.0.checked_sub(rhs.inner()).map(Self).and_then(Self::in_range)
    }

    /// `self - rhs` as a duration.
    #[must_use]
    pub fn signed_duration_since(self, rhs: Self) -> Duration {
        Duration::from_inner(self.0 - rhs.0)
    }

    /// `YYYY-MM-DDThh:mm:ss[.fff]+00:00`.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        self.to_rfc3339_opts(SecondsFormat::AutoSi, false)
    }

    /// RFC 3339 with the chosen fraction and `Z` or `+00:00` for the zero offset.
    #[must_use]
    pub fn to_rfc3339_opts(self, format: SecondsFormat, use_z: bool) -> String {
        let mut out = String::with_capacity(35);
        // Writing to a `String` cannot fail.
        let _ = write_rfc3339(&mut out, self.plain(), 0, format, use_z);
        out
    }

    /// Read an RFC 3339 date and time with an offset, as UTC.
    ///
    /// # Errors
    /// [`ParseError`] when the text is not RFC 3339.
    pub fn parse_rfc3339(text: &str) -> Result<Self, ParseError> {
        FixedDateTime::parse_rfc3339(text).map(FixedDateTime::to_utc)
    }

    /// Read an RFC 2822 date and time (HTTP dates, `Retry-After`, cookie expiry), as UTC.
    ///
    /// # Errors
    /// [`ParseError`] when the text is not RFC 2822.
    pub fn parse_rfc2822(text: &str) -> Result<Self, ParseError> {
        FixedDateTime::parse_rfc2822(text).map(FixedDateTime::to_utc)
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::UNIX_EPOCH
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_date(f, self.0.date())?;
        f.write_str("T")?;
        write_time(f, self.0.time())?;
        f.write_str("Z")
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_date(f, self.0.date())?;
        f.write_str(" ")?;
        write_time(f, self.0.time())?;
        f.write_str(" UTC")
    }
}

impl FromStr for Timestamp {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<Self> {
        FixedDateTime::from_str(s).map(FixedDateTime::to_utc)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{}", Rfc3339Z(*self)))
    }
}

struct Rfc3339Z(Timestamp);

impl fmt::Display for Rfc3339Z {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_rfc3339(f, self.0.plain(), 0, SecondsFormat::AutoSi, true)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Timestamp;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a formatted date and time string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Timestamp, E> {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self {
        Self(self.0 + rhs.inner())
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self {
        Self(self.0 - rhs.inner())
    }
}

impl Sub for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Duration {
        self.signed_duration_since(rhs)
    }
}

impl AddAssign<Duration> for Timestamp {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl SubAssign<Duration> for Timestamp {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl From<std::time::SystemTime> for Timestamp {
    fn from(value: std::time::SystemTime) -> Self {
        Self(UtcDateTime::from(value))
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(value: Timestamp) -> Self {
        Self::from(value.0)
    }
}

/// An instant together with the UTC offset its text was written in. Parsing keeps the offset so
/// the local date and the original spelling survive; everything else works on the instant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FixedDateTime {
    instant: Timestamp,
    offset: i32,
}

impl FixedDateTime {
    /// The local date and time `local` read at `offset_secs` east of UTC.
    ///
    /// # Errors
    /// [`ParseError`] when the offset is a day or more or the instant is out of range.
    pub fn from_local(local: NaiveDateTime, offset_secs: i32) -> Result<Self, ParseError> {
        if offset_secs <= -86_400 || offset_secs >= 86_400 {
            return Err(OUT_OF_RANGE);
        }
        let instant = local
            .plain()
            .checked_sub(Duration::seconds(i64::from(offset_secs)).inner())
            .map(Timestamp::from_plain)
            .and_then(Timestamp::in_range)
            .ok_or(OUT_OF_RANGE)?;
        Ok(Self { instant, offset: offset_secs })
    }

    fn local(self) -> PlainDateTime {
        self.instant
            .plain()
            .checked_add(Duration::seconds(i64::from(self.offset)).inner())
            .unwrap_or_else(|| self.instant.plain())
    }

    /// The instant in UTC.
    #[must_use]
    pub const fn to_utc(self) -> Timestamp {
        self.instant
    }

    /// The offset, in seconds east of UTC.
    #[must_use]
    pub const fn offset_seconds(self) -> i32 {
        self.offset
    }

    /// The local calendar date.
    #[must_use]
    pub fn date_naive(self) -> NaiveDate {
        NaiveDate::from_date(self.local().date())
    }

    /// Milliseconds since the epoch.
    #[must_use]
    pub fn timestamp_millis(self) -> i64 {
        self.instant.timestamp_millis()
    }

    /// `YYYY-MM-DDThh:mm:ss[.fff]+hh:mm`, in the local offset.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let mut out = String::with_capacity(35);
        // Writing to a `String` cannot fail.
        let _ = write_rfc3339(&mut out, self.local(), self.offset, SecondsFormat::AutoSi, false);
        out
    }

    /// Read an RFC 3339 date and time with an offset (`Z` or `+hh:mm`).
    ///
    /// # Errors
    /// [`ParseError`] when the text is not RFC 3339.
    pub fn parse_rfc3339(text: &str) -> Result<Self, ParseError> {
        let bytes = text.as_bytes();
        if bytes.len() < 19 {
            return Err(TOO_SHORT);
        }
        let fixed: &[u8; 19] = <&[u8; 19]>::try_from(&bytes[..19]).map_err(|_| TOO_SHORT)?;
        let digit = |i: usize| -> ParseResult<i64> {
            if fixed[i].is_ascii_digit() {
                Ok(i64::from(fixed[i] - b'0'))
            } else {
                Err(INVALID)
            }
        };
        let year = digit(0)? * 1000 + digit(1)? * 100 + digit(2)? * 10 + digit(3)?;
        if bytes.get(4) != Some(&b'-') {
            return Err(INVALID);
        }
        let month = digit(5)? * 10 + digit(6)?;
        if bytes.get(7) != Some(&b'-') {
            return Err(INVALID);
        }
        let day = digit(8)? * 10 + digit(9)?;
        if !matches!(bytes.get(10), Some(b't' | b'T' | b' ')) {
            return Err(INVALID);
        }
        let hour = digit(11)? * 10 + digit(12)?;
        if bytes.get(13) != Some(&b':') {
            return Err(INVALID);
        }
        let minute = digit(14)? * 10 + digit(15)?;
        if bytes.get(16) != Some(&b':') {
            return Err(INVALID);
        }
        let second = digit(17)? * 10 + digit(18)?;
        let mut parsed = Parsed {
            year: Some(year),
            month: Some(month),
            day: Some(day),
            hour: Some(hour),
            minute: Some(minute),
            second: Some(second),
            ..Parsed::default()
        };
        let mut rest = &text[19..];
        if bytes.get(19) == Some(&b'.') {
            let (r, nanos) = scan::nanosecond(&text[20..])?;
            rest = r;
            parsed.nanosecond = Some(nanos);
        }
        let (rest, offset) = scan::timezone_offset(rest, Colon::Required, true, true)?;
        if !rest.is_empty() {
            return Err(TOO_LONG);
        }
        parsed.offset = Some(offset);
        Self::from_parsed(&parsed)
    }

    fn from_parsed(parsed: &Parsed) -> ParseResult<Self> {
        let local = parsed.to_datetime()?;
        Self::from_local(NaiveDateTime::from_plain(local), parsed.offset.ok_or(IMPOSSIBLE)?)
    }

    /// Read an RFC 2822 date and time (`Tue, 1 Jul 2003 10:52:37 +0200`, `GMT`, comments).
    ///
    /// # Errors
    /// [`ParseError`] when the text is not RFC 2822.
    pub fn parse_rfc2822(text: &str) -> Result<Self, ParseError> {
        let mut parsed = Parsed::default();
        let mut s = text.trim_start();
        if let Ok((rest, weekday)) = scan::short_weekday(s) {
            s = rest.strip_prefix(',').ok_or(INVALID)?;
            parsed.weekday = Some(weekday);
        }
        s = s.trim_start();
        let (rest, day) = scan::number(s, 1, 2)?;
        parsed.day = Some(day);
        s = scan::space(rest)?;
        let (rest, month0) = scan::short_month0(s)?;
        parsed.month = Some(i64::from(month0) + 1);
        s = scan::space(rest)?;
        let before = s.len();
        let (rest, mut year) = scan::number(s, 2, usize::MAX)?;
        match (before - rest.len(), year) {
            (2, 0..=49) => year += 2000,
            (2, 50..=99) | (3, _) => year += 1900,
            _ => {}
        }
        parsed.year = Some(year);
        s = scan::space(rest)?;
        let (rest, hour) = scan::number(s, 2, 2)?;
        parsed.hour = Some(hour);
        s = scan::char(rest.trim_start(), b':')?.trim_start();
        let (rest, minute) = scan::number(s, 2, 2)?;
        parsed.minute = Some(minute);
        s = rest;
        if let Ok(after_colon) = scan::char(s.trim_start(), b':') {
            let (rest, second) = scan::number(after_colon, 2, 2)?;
            parsed.second = Some(second);
            s = rest;
        }
        s = scan::space(s)?;
        let (rest, offset) = scan::timezone_offset_2822(s)?;
        parsed.offset = Some(offset);
        s = rest;
        while let Ok(rest) = scan::comment_2822(s) {
            s = rest;
        }
        if !s.is_empty() {
            return Err(TOO_LONG);
        }
        let value = Self::from_parsed(&parsed)?;
        if let Some(weekday) = parsed.weekday {
            if value.local().date().weekday() != weekday {
                return Err(IMPOSSIBLE);
            }
        }
        Ok(value)
    }

    /// Parse `text` with a strftime-style `format` that contains `%:z` (see
    /// [`NaiveDate::parse_from_str`]).
    ///
    /// # Errors
    /// [`ParseError`] when the text does not match or is not a real date and time.
    pub fn parse_from_str(text: &str, format: &str) -> Result<Self, ParseError> {
        let parsed = Parsed::parse(text, format)?;
        Self::from_parsed(&parsed)
    }
}

impl FromStr for FixedDateTime {
    type Err = ParseError;

    /// The relaxed RFC 3339 reader: one-digit components, spaces between components, `T`, `t`
    /// or a space between date and time, `UTC` or an offset without colon.
    fn from_str(s: &str) -> ParseResult<Self> {
        let mut parsed = Parsed::default();
        let rest = parsed.year_month_day(s)?;
        let rest = match rest.as_bytes().first() {
            Some(b't' | b'T' | b' ') => &rest[1..],
            Some(_) => return Err(INVALID),
            None => return Err(TOO_SHORT),
        };
        let (rest, hour) = scan::field(rest, 2)?;
        parsed.hour = Some(hour);
        let rest = scan::char(rest.trim_start(), b':')?;
        let (rest, minute) = scan::field(rest, 2)?;
        parsed.minute = Some(minute);
        let rest = scan::char(rest.trim_start(), b':')?;
        let (mut rest, second) = scan::field(rest, 2)?;
        parsed.second = Some(second);
        if let Some(fraction) = rest.strip_prefix('.') {
            let (r, nanos) = scan::nanosecond(fraction)?;
            rest = r;
            parsed.nanosecond = Some(nanos);
        }
        let rest = rest.trim_start();
        let (rest, offset) = if rest.len() >= 3 && rest.as_bytes()[..3].eq_ignore_ascii_case(b"UTC") {
            (&rest[3..], 0)
        } else {
            scan::timezone_offset(rest, Colon::Loose, true, true)?
        };
        if !rest.is_empty() {
            return Err(TOO_LONG);
        }
        parsed.offset = Some(offset);
        Self::from_parsed(&parsed)
    }
}
