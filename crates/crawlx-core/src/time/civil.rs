//! Calendar dates and wall-clock times without a zone.

use super::error::{ParseError, ParseResult, INVALID, NOT_ENOUGH, OUT_OF_RANGE, TOO_LONG, TOO_SHORT};
use super::scan::{self, Colon};
use super::{Duration, Timestamp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use time::{Date, Month, PlainDateTime, Time, Weekday};

/// Smallest supported year.
const MIN_YEAR: i32 = -262_143;
/// Largest supported year.
const MAX_YEAR: i32 = 262_142;

/// Write `year-month-day`, with an explicit sign for years outside 0 to 9999.
pub(super) fn write_date(w: &mut impl fmt::Write, date: Date) -> fmt::Result {
    let year = date.year();
    if (0..=9999).contains(&year) {
        write!(w, "{year:04}")?;
    } else {
        write!(w, "{year:+05}")?;
    }
    write!(w, "-{:02}-{:02}", u8::from(date.month()), date.day())
}

/// Write `hh:mm:ss` and a fraction of one, three, six or nine digits when it is not zero.
pub(super) fn write_time(w: &mut impl fmt::Write, time: Time) -> fmt::Result {
    write!(w, "{:02}:{:02}:{:02}", time.hour(), time.minute(), time.second())?;
    let nano = time.nanosecond();
    if nano == 0 {
        Ok(())
    } else if nano.is_multiple_of(1_000_000) {
        write!(w, ".{:03}", nano / 1_000_000)
    } else if nano.is_multiple_of(1_000) {
        write!(w, ".{:06}", nano / 1_000)
    } else {
        write!(w, ".{nano:09}")
    }
}

/// A day count to add to or subtract from a [`NaiveDate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Days(pub u64);

impl Days {
    /// `days` days.
    #[must_use]
    pub const fn new(days: u64) -> Self {
        Self(days)
    }
}

/// An ISO 8601 week: the week-numbering year and the week, 1 to 53.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsoWeek {
    year: i32,
    week: u32,
}

impl IsoWeek {
    /// The week-numbering year.
    #[must_use]
    pub const fn year(self) -> i32 {
        self.year
    }

    /// The week, 1 to 53.
    #[must_use]
    pub const fn week(self) -> u32 {
        self.week
    }
}

/// A proleptic Gregorian calendar date without a zone (years -262143 to 262142).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NaiveDate(Date);

impl NaiveDate {
    /// The earliest supported date, January 1 of year -262143.
    pub const MIN: Self = Self(match Date::from_calendar_date(MIN_YEAR, Month::January, 1) {
        Ok(date) => date,
        Err(_) => Date::MIN,
    });

    /// The latest supported date, December 31 of year 262142.
    pub const MAX: Self = Self(match Date::from_calendar_date(MAX_YEAR, Month::December, 31) {
        Ok(date) => date,
        Err(_) => Date::MAX,
    });

    /// The date from year, month (1 to 12) and day, `None` when it does not exist.
    #[must_use]
    pub fn from_ymd_opt(year: i32, month: u32, day: u32) -> Option<Self> {
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
            return None;
        }
        let month = Month::try_from(u8::try_from(month).ok()?).ok()?;
        Date::from_calendar_date(year, month, u8::try_from(day).ok()?)
            .ok()
            .map(Self)
    }

    /// The date of an ISO week: year, week (1 to 53) and weekday.
    #[must_use]
    pub fn from_isoywd_opt(year: i32, week: u32, weekday: Weekday) -> Option<Self> {
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
            return None;
        }
        Date::from_iso_week_date(year, u8::try_from(week).ok()?, weekday)
            .ok()
            .map(Self)
    }

    pub(super) const fn from_date(date: Date) -> Self {
        Self(date)
    }

    pub(super) const fn date(self) -> Date {
        self.0
    }

    /// The year.
    #[must_use]
    pub const fn year(self) -> i32 {
        self.0.year()
    }

    /// The month, 1 to 12.
    #[must_use]
    pub fn month(self) -> u32 {
        u32::from(u8::from(self.0.month()))
    }

    /// The day of the month, 1 to 31.
    #[must_use]
    pub fn day(self) -> u32 {
        u32::from(self.0.day())
    }

    /// The day of the year, 1 to 366.
    #[must_use]
    pub fn ordinal(self) -> u32 {
        u32::from(self.0.ordinal())
    }

    /// The day of the week.
    #[must_use]
    pub const fn weekday(self) -> Weekday {
        self.0.weekday()
    }

    /// The ISO 8601 week the date falls in.
    #[must_use]
    pub fn iso_week(self) -> IsoWeek {
        let (year, week, _) = self.0.to_iso_week_date();
        IsoWeek {
            year,
            week: u32::from(week),
        }
    }

    /// The same year and month at `day`, `None` when the month has no such day.
    #[must_use]
    pub fn with_day(self, day: u32) -> Option<Self> {
        self.0.replace_day(u8::try_from(day).ok()?).ok().map(Self)
    }

    /// The next day, `None` at the end of the supported range.
    #[must_use]
    pub fn succ_opt(self) -> Option<Self> {
        self.0.next_day().filter(|d| d.year() <= MAX_YEAR).map(Self)
    }

    /// The previous day, `None` at the start of the supported range.
    #[must_use]
    pub fn pred_opt(self) -> Option<Self> {
        self.0.previous_day().filter(|d| d.year() >= MIN_YEAR).map(Self)
    }

    /// Add whole days, `None` on overflow.
    #[must_use]
    pub fn checked_add_days(self, days: Days) -> Option<Self> {
        let days = i64::try_from(days.0).ok()?;
        self.checked_add_signed(Duration::try_days(days)?)
    }

    /// Subtract whole days, `None` on overflow.
    #[must_use]
    pub fn checked_sub_days(self, days: Days) -> Option<Self> {
        let days = i64::try_from(days.0).ok()?;
        self.checked_sub_signed(Duration::try_days(days)?)
    }

    /// Add a duration (its time part is dropped), `None` on overflow.
    #[must_use]
    pub fn checked_add_signed(self, rhs: Duration) -> Option<Self> {
        let days = rhs.num_days();
        let julian = i64::from(self.0.to_julian_day()).checked_add(days)?;
        Date::from_julian_day(i32::try_from(julian).ok()?)
            .ok()
            .filter(|d| (MIN_YEAR..=MAX_YEAR).contains(&d.year()))
            .map(Self)
    }

    /// Subtract a duration (its time part is dropped), `None` on overflow.
    #[must_use]
    pub fn checked_sub_signed(self, rhs: Duration) -> Option<Self> {
        self.checked_add_signed(rhs.checked_neg()?)
    }

    /// `self - rhs` in whole days.
    #[must_use]
    pub fn signed_duration_since(self, rhs: Self) -> Duration {
        Duration::days(i64::from(self.0.to_julian_day()) - i64::from(rhs.0.to_julian_day()))
    }

    /// The date at `hour:minute:second`, `None` when the time does not exist.
    #[must_use]
    pub fn and_hms_opt(self, hour: u32, minute: u32, second: u32) -> Option<NaiveDateTime> {
        let time = Time::from_hms(
            u8::try_from(hour).ok()?,
            u8::try_from(minute).ok()?,
            u8::try_from(second).ok()?,
        )
        .ok()?;
        Some(NaiveDateTime(self.0.with_time(time)))
    }

    /// The date at `hour:minute:second.micro`, `None` when the time does not exist.
    #[must_use]
    pub fn and_hms_micro_opt(self, hour: u32, minute: u32, second: u32, micro: u32) -> Option<NaiveDateTime> {
        let time = Time::from_hms_micro(
            u8::try_from(hour).ok()?,
            u8::try_from(minute).ok()?,
            u8::try_from(second).ok()?,
            micro,
        )
        .ok()?;
        Some(NaiveDateTime(self.0.with_time(time)))
    }

    /// The date at midnight.
    #[must_use]
    pub const fn and_midnight(self) -> NaiveDateTime {
        NaiveDateTime(self.0.midnight())
    }

    /// Parse `text` with a strftime-style `format` made of `%Y`, `%m`, `%d`, `%H`, `%M`, `%S`
    /// and literals; the same grammar as before the facade (white space in the format matches
    /// any white space, numbers take leading white space).
    ///
    /// # Errors
    /// [`ParseError`] when the text does not match or is not a real date.
    pub fn parse_from_str(text: &str, format: &str) -> Result<Self, ParseError> {
        Parsed::parse(text, format)?.to_date().map(Self)
    }
}

impl Default for NaiveDate {
    fn default() -> Self {
        Self(Date::from_calendar_date(1970, Month::January, 1).unwrap_or(Date::MIN))
    }
}

impl fmt::Debug for NaiveDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_date(f, self.0)
    }
}

impl fmt::Display for NaiveDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_date(f, self.0)
    }
}

impl FromStr for NaiveDate {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<Self> {
        let mut parsed = Parsed::default();
        let rest = parsed.year_month_day(s)?;
        if !rest.trim_start().is_empty() {
            return Err(TOO_LONG);
        }
        parsed.to_date().map(Self)
    }
}

impl Serialize for NaiveDate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NaiveDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = NaiveDate;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a formatted date string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<NaiveDate, E> {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

impl std::ops::Sub for NaiveDate {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Duration {
        self.signed_duration_since(rhs)
    }
}

/// A time of day without a zone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NaiveTime(Time);

impl NaiveTime {
    /// Parse `text` with a strftime-style `format` (see [`NaiveDate::parse_from_str`]).
    ///
    /// # Errors
    /// [`ParseError`] when the text does not match or is not a real time.
    pub fn parse_from_str(text: &str, format: &str) -> Result<Self, ParseError> {
        Parsed::parse(text, format)?.to_time().map(|(t, _)| Self(t))
    }

    /// The hour, 0 to 23.
    #[must_use]
    pub fn hour(self) -> u32 {
        u32::from(self.0.hour())
    }

    /// The minute, 0 to 59.
    #[must_use]
    pub fn minute(self) -> u32 {
        u32::from(self.0.minute())
    }
}

/// A calendar date and time of day without a zone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NaiveDateTime(PlainDateTime);

impl NaiveDateTime {
    /// The date part.
    #[must_use]
    pub const fn date(self) -> NaiveDate {
        NaiveDate(self.0.date())
    }

    /// The time part.
    #[must_use]
    pub const fn time(self) -> NaiveTime {
        NaiveTime(self.0.time())
    }

    /// Read the value as UTC.
    #[must_use]
    pub fn and_utc(self) -> Timestamp {
        Timestamp::from_plain(self.0)
    }

    pub(super) const fn plain(self) -> PlainDateTime {
        self.0
    }

    pub(super) const fn from_plain(value: PlainDateTime) -> Self {
        Self(value)
    }

    /// The hour, 0 to 23.
    #[must_use]
    pub fn hour(self) -> u32 {
        u32::from(self.0.hour())
    }

    /// The minute, 0 to 59.
    #[must_use]
    pub fn minute(self) -> u32 {
        u32::from(self.0.minute())
    }

    /// The second, 0 to 59.
    #[must_use]
    pub fn second(self) -> u32 {
        u32::from(self.0.second())
    }

    /// Parse `text` with a strftime-style `format` (see [`NaiveDate::parse_from_str`]).
    ///
    /// # Errors
    /// [`ParseError`] when the text does not match or is not a real date and time.
    pub fn parse_from_str(text: &str, format: &str) -> Result<Self, ParseError> {
        Parsed::parse(text, format)?.to_datetime().map(Self)
    }
}

impl fmt::Debug for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_date(f, self.0.date())?;
        f.write_str("T")?;
        write_time(f, self.0.time())
    }
}

impl fmt::Display for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_date(f, self.0.date())?;
        f.write_str(" ")?;
        write_time(f, self.0.time())
    }
}

/// Date and time fields read from a text, before they are checked against each other.
#[derive(Default)]
pub(super) struct Parsed {
    pub(super) year: Option<i64>,
    pub(super) month: Option<i64>,
    pub(super) day: Option<i64>,
    pub(super) hour: Option<i64>,
    pub(super) minute: Option<i64>,
    pub(super) second: Option<i64>,
    pub(super) nanosecond: Option<u32>,
    pub(super) offset: Option<i32>,
    pub(super) weekday: Option<Weekday>,
}

impl Parsed {
    /// `year - month - day` with optional white space around the numbers (the date grammar of
    /// [`NaiveDate::from_str`] and of the relaxed RFC 3339 reader).
    pub(super) fn year_month_day<'a>(&mut self, s: &'a str) -> ParseResult<&'a str> {
        let (s, year) = scan::year(s)?;
        self.year = Some(year);
        let s = scan::char(s.trim_start(), b'-')?;
        let (s, month) = scan::field(s, 2)?;
        self.month = Some(month);
        let s = scan::char(s.trim_start(), b'-')?;
        let (s, day) = scan::field(s, 2)?;
        self.day = Some(day);
        Ok(s)
    }

    /// Read `text` as `format`, which may contain `%Y %m %d %H %M %S %:z` and literals.
    pub(super) fn parse(text: &str, format: &str) -> ParseResult<Self> {
        let mut parsed = Self::default();
        let mut s = text;
        let mut chars = format.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if c == '%' {
                let Some((_, spec)) = chars.next() else {
                    return Err(INVALID);
                };
                match spec {
                    'Y' => {
                        let (rest, v) = scan::year(s)?;
                        s = rest;
                        parsed.year = Some(v);
                    }
                    'm' | 'd' | 'H' | 'M' | 'S' => {
                        let (rest, v) = scan::field(s, 2)?;
                        s = rest;
                        match spec {
                            'm' => parsed.month = Some(v),
                            'd' => parsed.day = Some(v),
                            'H' => parsed.hour = Some(v),
                            'M' => parsed.minute = Some(v),
                            _ => parsed.second = Some(v),
                        }
                    }
                    ':' => {
                        if !matches!(chars.next(), Some((_, 'z'))) {
                            return Err(INVALID);
                        }
                        let (rest, offset) =
                            scan::timezone_offset(s.trim_start(), Colon::Loose, false, true)?;
                        s = rest;
                        parsed.offset = Some(offset);
                    }
                    _ => return Err(INVALID),
                }
            } else if c.is_whitespace() {
                s = s.trim_start();
            } else {
                let literal = &format[i..i + c.len_utf8()];
                if s.len() < literal.len() {
                    return Err(TOO_SHORT);
                }
                s = s.strip_prefix(literal).ok_or(INVALID)?;
            }
        }
        if s.is_empty() {
            Ok(parsed)
        } else {
            Err(TOO_LONG)
        }
    }

    pub(super) fn to_date(&self) -> ParseResult<Date> {
        let (Some(year), Some(month), Some(day)) = (self.year, self.month, self.day) else {
            return Err(NOT_ENOUGH);
        };
        let year = i32::try_from(year).map_err(|_| OUT_OF_RANGE)?;
        NaiveDate::from_ymd_opt(
            year,
            u32::try_from(month).map_err(|_| OUT_OF_RANGE)?,
            u32::try_from(day).map_err(|_| OUT_OF_RANGE)?,
        )
        .map(NaiveDate::date)
        .ok_or(OUT_OF_RANGE)
    }

    /// The time of day, and whether the second was a leap second (`60`, read as `59` plus one).
    pub(super) fn to_time(&self) -> ParseResult<(Time, bool)> {
        let (Some(hour), Some(minute)) = (self.hour, self.minute) else {
            return Err(NOT_ENOUGH);
        };
        let second = self.second.unwrap_or(0);
        let leap = second == 60;
        let second = if leap { 59 } else { second };
        let nanosecond = self.nanosecond.unwrap_or(0);
        Time::from_hms_nano(
            u8::try_from(hour).map_err(|_| OUT_OF_RANGE)?,
            u8::try_from(minute).map_err(|_| OUT_OF_RANGE)?,
            u8::try_from(second).map_err(|_| OUT_OF_RANGE)?,
            nanosecond,
        )
        .map(|t| (t, leap))
        .map_err(|_| OUT_OF_RANGE)
    }

    pub(super) fn to_datetime(&self) -> ParseResult<PlainDateTime> {
        let date = self.to_date();
        let time = self.to_time();
        let (date, (time, leap)) = match (date, time) {
            (Ok(d), Ok(t)) => (d, t),
            (Err(e), _) | (_, Err(e)) => return Err(e),
        };
        let value = date.with_time(time);
        if leap {
            value
                .checked_add(Duration::seconds(1).inner())
                .ok_or(OUT_OF_RANGE)
        } else {
            Ok(value)
        }
    }
}
