//! A signed length of time.

use super::error::OutOfRangeError;
use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, Mul, Neg, Sub, SubAssign};
use time::SignedDuration;

/// Seconds in the largest duration, as `i64::MAX` milliseconds.
const MAX_SECS: i64 = i64::MAX / 1000;
const MAX_NANOS: i32 = 807_000_000;

/// A signed length of time with nanosecond resolution, up to `i64::MAX` milliseconds either
/// way.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Duration(SignedDuration);

impl Duration {
    /// The zero duration.
    pub const ZERO: Self = Self(SignedDuration::ZERO);
    /// The longest duration.
    pub const MAX: Self = Self(SignedDuration::new(MAX_SECS, MAX_NANOS));
    /// The shortest (most negative) duration.
    pub const MIN: Self = Self(SignedDuration::new(-MAX_SECS, -MAX_NANOS));

    pub(super) const fn inner(self) -> SignedDuration {
        self.0
    }

    pub(super) const fn from_inner(value: SignedDuration) -> Self {
        Self(value)
    }

    fn checked(value: SignedDuration) -> Option<Self> {
        (value <= Self::MAX.0 && value >= Self::MIN.0).then_some(Self(value))
    }

    /// The zero duration.
    #[must_use]
    pub const fn zero() -> Self {
        Self::ZERO
    }

    /// `weeks` weeks. Panics on overflow, like the operators.
    #[must_use]
    pub fn weeks(weeks: i64) -> Self {
        Self(SignedDuration::weeks(weeks))
    }

    /// `days` days.
    #[must_use]
    pub fn days(days: i64) -> Self {
        Self(SignedDuration::days(days))
    }

    /// `hours` hours.
    #[must_use]
    pub fn hours(hours: i64) -> Self {
        Self(SignedDuration::hours(hours))
    }

    /// `minutes` minutes.
    #[must_use]
    pub fn minutes(minutes: i64) -> Self {
        Self(SignedDuration::minutes(minutes))
    }

    /// `seconds` seconds.
    #[must_use]
    pub fn seconds(seconds: i64) -> Self {
        Self(SignedDuration::seconds(seconds))
    }

    /// `milliseconds` milliseconds.
    #[must_use]
    pub fn milliseconds(milliseconds: i64) -> Self {
        Self(SignedDuration::milliseconds(milliseconds))
    }

    /// `microseconds` microseconds.
    #[must_use]
    pub fn microseconds(microseconds: i64) -> Self {
        Self(SignedDuration::microseconds(microseconds))
    }

    /// `nanoseconds` nanoseconds.
    #[must_use]
    pub fn nanoseconds(nanoseconds: i64) -> Self {
        Self(SignedDuration::nanoseconds(nanoseconds))
    }

    /// `days` days, `None` when out of range.
    #[must_use]
    pub fn try_days(days: i64) -> Option<Self> {
        days.checked_mul(86_400).and_then(Self::try_seconds)
    }

    /// `hours` hours, `None` when out of range.
    #[must_use]
    pub fn try_hours(hours: i64) -> Option<Self> {
        hours.checked_mul(3_600).and_then(Self::try_seconds)
    }

    /// `minutes` minutes, `None` when out of range.
    #[must_use]
    pub fn try_minutes(minutes: i64) -> Option<Self> {
        minutes.checked_mul(60).and_then(Self::try_seconds)
    }

    /// `seconds` seconds, `None` when out of range.
    #[must_use]
    pub fn try_seconds(seconds: i64) -> Option<Self> {
        Self::checked(SignedDuration::seconds(seconds))
    }

    /// `milliseconds` milliseconds, `None` when out of range.
    #[must_use]
    pub fn try_milliseconds(milliseconds: i64) -> Option<Self> {
        Self::checked(SignedDuration::milliseconds(milliseconds))
    }

    /// Whole weeks.
    #[must_use]
    pub const fn num_weeks(self) -> i64 {
        self.0.whole_weeks()
    }

    /// Whole days.
    #[must_use]
    pub const fn num_days(self) -> i64 {
        self.0.whole_days()
    }

    /// Whole hours.
    #[must_use]
    pub const fn num_hours(self) -> i64 {
        self.0.whole_hours()
    }

    /// Whole minutes.
    #[must_use]
    pub const fn num_minutes(self) -> i64 {
        self.0.whole_minutes()
    }

    /// Whole seconds (towards zero).
    #[must_use]
    pub const fn num_seconds(self) -> i64 {
        self.0.whole_seconds()
    }

    /// Whole milliseconds (towards zero). Saturates only for the extreme durations, which no
    /// caller produces.
    #[must_use]
    pub fn num_milliseconds(self) -> i64 {
        i64::try_from(self.0.whole_milliseconds()).unwrap_or(if self.0.is_negative() { i64::MIN } else { i64::MAX })
    }

    /// Whole microseconds, `None` when they do not fit an `i64`.
    #[must_use]
    pub fn num_microseconds(self) -> Option<i64> {
        i64::try_from(self.0.whole_microseconds()).ok()
    }

    /// Whole nanoseconds, `None` when they do not fit an `i64`.
    #[must_use]
    pub fn num_nanoseconds(self) -> Option<i64> {
        i64::try_from(self.0.whole_nanoseconds()).ok()
    }

    /// Whether the duration is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    /// Whether the duration is below zero.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    /// The absolute value.
    #[must_use]
    pub const fn abs(self) -> Self {
        Self(self.0.abs())
    }

    /// `self + rhs`, `None` on overflow.
    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).and_then(Self::checked)
    }

    /// `self - rhs`, `None` on overflow.
    #[must_use]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).and_then(Self::checked)
    }

    /// `-self`, `None` on overflow.
    #[must_use]
    pub fn checked_neg(self) -> Option<Self> {
        self.0.checked_neg().and_then(Self::checked)
    }

    /// Convert a [`std::time::Duration`].
    ///
    /// # Errors
    /// [`OutOfRangeError`] above the longest duration.
    pub fn from_std(duration: std::time::Duration) -> Result<Self, OutOfRangeError> {
        let secs = i64::try_from(duration.as_secs()).map_err(|_| OutOfRangeError(()))?;
        let nanos = i32::try_from(duration.subsec_nanos()).map_err(|_| OutOfRangeError(()))?;
        Self::checked(SignedDuration::new(secs, nanos)).ok_or(OutOfRangeError(()))
    }

    /// Convert to a [`std::time::Duration`].
    ///
    /// # Errors
    /// [`OutOfRangeError`] for a negative duration.
    pub fn to_std(self) -> Result<std::time::Duration, OutOfRangeError> {
        if self.0.is_negative() {
            return Err(OutOfRangeError(()));
        }
        Ok(self.0.unsigned_abs())
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let negative = self.0.is_negative();
        let abs = self.0.unsigned_abs();
        f.write_str(if negative { "-P" } else { "P" })?;
        if abs.is_zero() {
            return f.write_str("0D");
        }
        write!(f, "T{}", abs.as_secs())?;
        let mut nanos = abs.subsec_nanos();
        if nanos > 0 {
            let mut figures = 9usize;
            while nanos.is_multiple_of(10) {
                nanos /= 10;
                figures -= 1;
            }
            write!(f, ".{nanos:0figures$}")?;
        }
        f.write_str("S")
    }
}

impl Add for Duration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Duration {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for Duration {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Neg for Duration {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl Mul<i32> for Duration {
    type Output = Self;

    fn mul(self, rhs: i32) -> Self {
        Self(self.0 * rhs)
    }
}

impl Div<i32> for Duration {
    type Output = Self;

    fn div(self, rhs: i32) -> Self {
        Self(self.0 / rhs)
    }
}

impl Sum for Duration {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}
