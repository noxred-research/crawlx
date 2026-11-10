//! Monitor schedules: the compatibility API's `MonitorSchedule` request object (`{cron | text, timezone}`)
//! parsed into a [`Schedule`] that answers "when is the next run after this instant".
//!
//! # Request form
//!
//! ```json
//! { "cron": "7-59/15 * * * *", "timezone": "Europe/Berlin" }
//! { "text": "daily at 9am",   "timezone": "America/New_York" }
//! ```
//!
//! Exactly one of `cron` and `text` is required; `timezone` is an IANA name and defaults to
//! `UTC`. [`Schedule`] serializes back to this form, so a stored request round-trips.
//!
//! # Cron
//!
//! Exactly five fields (`minute hour day-of-month month day-of-week`) in the `croner` dialect:
//! lists, ranges, steps (`*/15`, `7-59/15`), month and weekday names. Seconds, years and
//! `@aliases` are rejected. As in Vixie cron a day-of-month and a day-of-week restriction
//! together match either.
//!
//! # Natural text
//!
//! Case-insensitive, whitespace-insensitive; anything else is [`ScheduleError::InvalidText`].
//!
//! ```text
//! text     = hourly | daily | weekly | interval
//! hourly   = "hourly" [ anchor ] | "every hour" [ anchor ]
//! daily    = ( "daily" | "every day" ) [ "at" time ]
//! weekly   = ( "weekly" [ "on" weekday ] | "every week" [ "on" weekday ] | "every" weekday ) [ "at" time ]
//! interval = "every" [ N ] ( "minute"|"minutes"|"min"|"mins" | "hour"|"hours"|"hr"|"hrs" ) [ anchor ]
//! anchor   = [ "starting" ] "at" ":MM"            ; minute of the hour the series starts on
//! time     = "noon" | "midnight" | H | H:MM | H am|pm | H:MM am|pm   ; 24 h clock without am/pm
//! weekday  = sunday|sun|monday|mon|tuesday|tue|tues|wednesday|wed|thursday|thu|thur|thurs
//!          | friday|fri|saturday|sat
//! ```
//!
//! | text | cron |
//! |---|---|
//! | `every 30 minutes` | `*/30 * * * *` |
//! | `every 15 minutes starting at :07` | `7-59/15 * * * *` |
//! | `hourly` | `0 * * * *` |
//! | `every 2 hours` | `0 */2 * * *` |
//! | `daily` | `0 0 * * *` |
//! | `daily at 9am` / `daily at 9:00` | `0 9 * * *` |
//! | `daily at 5:30 PM` | `30 17 * * *` |
//! | `weekly` | `0 0 * * 0` (Sunday, like cron's `@weekly`) |
//! | `every monday at 9am` | `0 9 * * 1` |
//!
//! Minute intervals above 59 must be a multiple of 60 (`every 120 minutes` is `every 2 hours`);
//! hour intervals run 1 to 24. Step intervals restart at the top of the next hour/day exactly as
//! cron does, so `every 45 minutes` fires at :00 and :45.
//!
//! # Minimum interval and time zones
//!
//! No two consecutive runs may be closer than [`MIN_INTERVAL_SECS`] (5 minutes); the check walks
//! the schedule from a fixed reference instant, so it is deterministic.
//! [`ScheduleError::TooFrequent`] reports the shortest gap found. Times are evaluated in the
//! schedule's zone with the DST rules of `croner` (OCPS / Vixie cron): a fixed-time job whose
//! wall time falls into a spring-forward gap fires once, right after the gap, on the same day; a
//! fixed-time job inside a fall-back overlap fires once, at the first occurrence; wildcard and
//! step jobs skip a gap and fire for both passes of an overlap.
//!
//! This module never reads the wall clock: every instant is an argument.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use croner::parser::{CronParser, Seconds, Year};
use croner::Cron;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Shortest allowed gap between two consecutive runs, in seconds (5 minutes).
pub const MIN_INTERVAL_SECS: i64 = 300;

/// Zone used when the request names none.
pub const DEFAULT_TIMEZONE: &str = "UTC";

/// Most occurrences the minimum-interval check walks.
const SAMPLE_OCCURRENCES: usize = 1_000;
/// The interval check stops this many seconds after its reference instant (400 days).
const SAMPLE_HORIZON_SECS: i64 = 400 * 86_400;
/// Reference instant of the interval check and of [`Schedule::runs_per_30_days`]: 2024-01-01T00:00:00Z.
const REFERENCE_UNIX: i64 = 1_704_067_200;

/// Why a schedule request was rejected.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScheduleError {
    /// Neither `cron` nor `text` was given.
    #[error("schedule needs one of `cron` or `text`")]
    Missing,
    /// Both `cron` and `text` were given.
    #[error("schedule takes either `cron` or `text`, not both")]
    Ambiguous,
    /// The cron expression is not five valid fields.
    #[error("invalid cron expression {expression:?}: {reason}")]
    InvalidCron {
        /// The expression as sent.
        expression: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The text is outside the documented grammar.
    #[error("unsupported schedule text {text:?}: {reason}")]
    InvalidText {
        /// The text as sent.
        text: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The timezone is not an IANA zone name.
    #[error("unknown timezone {0:?}")]
    UnknownTimezone(String),
    /// Two consecutive runs are closer than [`MIN_INTERVAL_SECS`].
    #[error(
        "schedule runs every {min_gap_secs} s at its shortest; the minimum interval is 5 minutes (300 s)"
    )]
    TooFrequent {
        /// The shortest gap between consecutive runs found, in seconds.
        min_gap_secs: u64,
    },
}

impl ScheduleError {
    /// The request member the error is about: `cron`, `text`, `timezone`, or `""` for the whole
    /// schedule object (JSON-pointer suffix for the API's `details[].path`).
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::Missing | Self::Ambiguous | Self::TooFrequent { .. } => "",
            Self::InvalidCron { .. } => "cron",
            Self::InvalidText { .. } => "text",
            Self::UnknownTimezone(_) => "timezone",
        }
    }

    /// Stable machine code for the API (`required`, `invalid`, `too_frequent`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing => "required",
            Self::Ambiguous
            | Self::InvalidCron { .. }
            | Self::InvalidText { .. }
            | Self::UnknownTimezone(_) => "invalid",
            Self::TooFrequent { .. } => "too_frequent",
        }
    }
}

/// The request form of a schedule (`MonitorSchedule`).
#[derive(Clone, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct ScheduleSpec {
    /// Five-field cron expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
    /// Natural-language schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// IANA zone name; `UTC` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// A validated schedule: a five-field cron expression in an IANA zone.
#[derive(Clone, Debug)]
pub struct Schedule {
    cron: Cron,
    expression: String,
    zone: Tz,
    spec: ScheduleSpec,
}

impl PartialEq for Schedule {
    fn eq(&self, other: &Self) -> bool {
        self.expression == other.expression && self.zone == other.zone
    }
}

impl Eq for Schedule {}

impl Serialize for Schedule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.spec.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Schedule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let spec = ScheduleSpec::deserialize(deserializer)?;
        Self::parse(&spec).map_err(serde::de::Error::custom)
    }
}

fn reference() -> DateTime<Utc> {
    DateTime::from_timestamp(REFERENCE_UNIX, 0).unwrap_or_default()
}

fn zone_of(name: &str) -> Result<Tz, ScheduleError> {
    name.parse::<Tz>()
        .map_err(|_| ScheduleError::UnknownTimezone(name.to_owned()))
}

fn parse_cron(expression: &str) -> Result<(Cron, String), ScheduleError> {
    let fields: Vec<&str> = expression.split_whitespace().collect();
    let invalid = |reason: String| ScheduleError::InvalidCron {
        expression: expression.to_owned(),
        reason,
    };
    if fields.len() != 5 {
        return Err(invalid(format!(
            "expected five fields (minute hour day-of-month month day-of-week), found {}",
            fields.len()
        )));
    }
    let normalized = fields.join(" ");
    let parser = CronParser::builder()
        .seconds(Seconds::Disallowed)
        .year(Year::Disallowed)
        .build();
    let cron = parser.parse(&normalized).map_err(|e| invalid(e.to_string()))?;
    Ok((cron, normalized))
}

impl Schedule {
    /// Validate a request.
    ///
    /// # Errors
    /// [`ScheduleError`] for a missing or ambiguous schedule, an invalid cron expression or text,
    /// an unknown timezone, or a schedule that fires more often than every 5 minutes.
    pub fn parse(spec: &ScheduleSpec) -> Result<Self, ScheduleError> {
        let schedule = Self::build(spec)?;
        schedule.check_interval()?;
        Ok(schedule)
    }

    /// Rebuild a schedule from the normalized `cron` and `timezone` columns of a stored monitor.
    /// The minimum interval was enforced when the monitor was written, so it is not re-checked.
    ///
    /// # Errors
    /// [`ScheduleError::InvalidCron`] or [`ScheduleError::UnknownTimezone`] for corrupt rows.
    pub fn from_stored(cron: &str, timezone: &str) -> Result<Self, ScheduleError> {
        Self::build(&ScheduleSpec {
            cron: Some(cron.to_owned()),
            text: None,
            timezone: Some(timezone.to_owned()),
        })
    }

    fn build(spec: &ScheduleSpec) -> Result<Self, ScheduleError> {
        let zone_name = spec.timezone.as_deref().unwrap_or(DEFAULT_TIMEZONE);
        let zone = zone_of(zone_name)?;
        let (cron, expression, kept_cron, kept_text) = match (&spec.cron, &spec.text) {
            (None, None) => return Err(ScheduleError::Missing),
            (Some(_), Some(_)) => return Err(ScheduleError::Ambiguous),
            (Some(c), None) => {
                let (cron, expression) = parse_cron(c)?;
                (cron, expression, Some(c.trim().to_owned()), None)
            }
            (None, Some(t)) => {
                let expression = text_to_cron(t).map_err(|reason| ScheduleError::InvalidText {
                    text: t.clone(),
                    reason,
                })?;
                let (cron, expression) = parse_cron(&expression)?;
                (cron, expression, None, Some(t.trim().to_owned()))
            }
        };
        Ok(Self {
            cron,
            expression,
            zone,
            spec: ScheduleSpec {
                cron: kept_cron,
                text: kept_text,
                timezone: Some(zone.name().to_owned()),
            },
        })
    }

    /// The normalized five-field cron expression.
    #[must_use]
    pub fn cron(&self) -> &str {
        &self.expression
    }

    /// The IANA zone name the cron is evaluated in.
    #[must_use]
    pub fn timezone(&self) -> &str {
        self.zone.name()
    }

    /// The request form (`cron` or `text`, and the zone) this schedule serializes to.
    #[must_use]
    pub const fn spec(&self) -> &ScheduleSpec {
        &self.spec
    }

    /// The first run strictly after `after`, `None` when the schedule has no later run.
    ///
    /// Deterministic: the same schedule and instant always give the same answer. Feed the
    /// returned instant back in to walk the series.
    #[must_use]
    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let local = after.with_timezone(&self.zone);
        self.cron
            .find_next_occurrence(&local, false)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }

    /// How many runs fall in 30 days, estimated from the schedule's first occurrences after a
    /// fixed reference instant (deterministic). Used for credit estimates.
    #[must_use]
    pub fn runs_per_30_days(&self) -> u64 {
        let start = reference();
        let mut at = start;
        let mut count: u64 = 0;
        let mut last = start;
        for _ in 0..200 {
            let Some(next) = self.next_after(at) else { break };
            if (next - start).num_seconds() > SAMPLE_HORIZON_SECS {
                break;
            }
            count = count.saturating_add(1);
            last = next;
            at = next;
        }
        let span = (last - start).num_seconds();
        if count < 2 || span <= 0 {
            return count.min(1);
        }
        // runs per second times the seconds of 30 days, rounded up
        let window = 30_i64 * 86_400;
        let numerator = u64::try_from(window).unwrap_or(0).saturating_mul(count);
        let denominator = u64::try_from(span).unwrap_or(1).max(1);
        numerator.div_ceil(denominator)
    }

    fn check_interval(&self) -> Result<(), ScheduleError> {
        let start = reference();
        let mut at = start;
        let mut previous: Option<DateTime<Utc>> = None;
        let mut shortest: Option<i64> = None;
        for _ in 0..SAMPLE_OCCURRENCES {
            let Some(next) = self.next_after(at) else { break };
            if (next - start).num_seconds() > SAMPLE_HORIZON_SECS {
                break;
            }
            if let Some(p) = previous {
                let gap = (next - p).num_seconds();
                shortest = Some(shortest.map_or(gap, |s| s.min(gap)));
                if gap < MIN_INTERVAL_SECS {
                    break;
                }
            }
            previous = Some(next);
            at = next;
        }
        match shortest {
            Some(gap) if gap < MIN_INTERVAL_SECS => Err(ScheduleError::TooFrequent {
                min_gap_secs: u64::try_from(gap).unwrap_or(0),
            }),
            _ => Ok(()),
        }
    }
}

// ---- natural text -------------------------------------------------------------------------

/// Cursor over the lower-cased words of a schedule text.
struct Words<'a> {
    words: Vec<&'a str>,
    at: usize,
}

impl<'a> Words<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.words.get(self.at).copied()
    }

    fn take(&mut self) -> Option<&'a str> {
        let w = self.peek();
        if w.is_some() {
            self.at += 1;
        }
        w
    }

    fn eat(&mut self, word: &str) -> bool {
        if self.peek() == Some(word) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn finish(&self) -> Result<(), String> {
        match self.peek() {
            None => Ok(()),
            Some(w) => Err(format!("unexpected `{w}`")),
        }
    }
}

fn weekday(word: &str) -> Option<u8> {
    Some(match word {
        "sunday" | "sun" => 0,
        "monday" | "mon" => 1,
        "tuesday" | "tue" | "tues" => 2,
        "wednesday" | "wed" => 3,
        "thursday" | "thu" | "thur" | "thurs" => 4,
        "friday" | "fri" => 5,
        "saturday" | "sat" => 6,
        _ => return None,
    })
}

/// `:MM` anchor, optionally introduced by `starting at` / `at`.
fn minute_anchor(w: &mut Words<'_>) -> Result<Option<u32>, String> {
    let introduced = if w.eat("starting") {
        if !w.eat("at") {
            return Err("expected `at` after `starting`".to_owned());
        }
        true
    } else {
        w.eat("at")
    };
    if !introduced {
        return Ok(None);
    }
    let token = w.take().ok_or("expected `:MM` after `at`")?;
    let minute = token
        .strip_prefix(':')
        .and_then(|m| m.parse::<u32>().ok())
        .filter(|m| *m < 60)
        .ok_or_else(|| format!("`{token}` is not a minute anchor like `:07`"))?;
    Ok(Some(minute))
}

/// `at <time>` clause; `None` when the next word is not `at`.
fn at_time(w: &mut Words<'_>) -> Result<Option<(u32, u32)>, String> {
    if !w.eat("at") {
        return Ok(None);
    }
    let token = w.take().ok_or("expected a time after `at`")?;
    match token {
        "noon" => return Ok(Some((12, 0))),
        "midnight" => return Ok(Some((0, 0))),
        _ => {}
    }
    let (digits, mut meridiem) = match token.strip_suffix("am") {
        Some(rest) => (rest, Some(false)),
        None => match token.strip_suffix("pm") {
            Some(rest) => (rest, Some(true)),
            None => (token, None),
        },
    };
    if meridiem.is_none() {
        match w.peek() {
            Some("am") => {
                w.take();
                meridiem = Some(false);
            }
            Some("pm") => {
                w.take();
                meridiem = Some(true);
            }
            _ => {}
        }
    }
    let bad = || format!("`{token}` is not a time like `9am`, `9:00`, `17:45` or `5:30 PM`");
    let (hour_text, minute_text) = digits
        .split_once(':')
        .map_or((digits, None), |(h, m)| (h, Some(m)));
    let hour: u32 = hour_text.parse().map_err(|_| bad())?;
    let minute: u32 = match minute_text {
        None => 0,
        Some(m) if m.len() == 2 => m.parse().map_err(|_| bad())?,
        Some(_) => return Err(bad()),
    };
    if minute > 59 {
        return Err(bad());
    }
    let hour24 = match meridiem {
        Some(pm) => {
            if !(1..=12).contains(&hour) {
                return Err(format!("hour {hour} is outside 1-12 with am/pm"));
            }
            (hour % 12) + if pm { 12 } else { 0 }
        }
        None => {
            if hour > 23 {
                return Err(format!("hour {hour} is outside 0-23"));
            }
            hour
        }
    };
    Ok(Some((hour24, minute)))
}

fn weekly(w: &mut Words<'_>, day: Option<u8>) -> Result<String, String> {
    let dow = match day {
        Some(d) => d,
        None => {
            if w.eat("on") {
                let name = w.take().ok_or("expected a weekday after `on`")?;
                weekday(name).ok_or_else(|| format!("`{name}` is not a weekday"))?
            } else {
                0
            }
        }
    };
    let (h, m) = at_time(w)?.unwrap_or((0, 0));
    w.finish()?;
    Ok(format!("{m} {h} * * {dow}"))
}

fn interval(w: &mut Words<'_>) -> Result<String, String> {
    let count = match w.peek().and_then(|t| t.parse::<u32>().ok()) {
        Some(n) => {
            w.take();
            n
        }
        None => 1,
    };
    let unit = w.take().ok_or("expected `minutes` or `hours`")?;
    let anchor = minute_anchor(w)?;
    w.finish()?;
    let minutes_unit = matches!(unit, "minute" | "minutes" | "min" | "mins");
    let hours_unit = matches!(unit, "hour" | "hours" | "hr" | "hrs");
    if !minutes_unit && !hours_unit {
        return Err(format!("`{unit}` is not `minutes` or `hours`"));
    }
    let hours = if minutes_unit {
        match count {
            0 => return Err("the interval must be at least 1".to_owned()),
            1 if anchor.is_none() => return Ok("* * * * *".to_owned()),
            1..=59 => {
                return Ok(match anchor {
                    Some(a) => format!("{a}-59/{count} * * * *"),
                    None => format!("*/{count} * * * *"),
                });
            }
            n if n % 60 == 0 => n / 60,
            _ => return Err("minute intervals above 59 must be a multiple of 60".to_owned()),
        }
    } else {
        count
    };
    let minute = anchor.unwrap_or(0);
    match hours {
        0 => Err("the interval must be at least 1".to_owned()),
        1 => Ok(format!("{minute} * * * *")),
        2..=23 => Ok(format!("{minute} */{hours} * * *")),
        24 => Ok(format!("{minute} 0 * * *")),
        _ => Err("hour intervals run from 1 to 24; use `daily` or `weekly` for longer ones".to_owned()),
    }
}

/// The five-field cron expression of a natural-language schedule.
fn text_to_cron(text: &str) -> Result<String, String> {
    let lowered = text.to_ascii_lowercase();
    let mut w = Words {
        words: lowered.split_whitespace().collect(),
        at: 0,
    };
    let first = w.take().ok_or("the text is empty")?;
    match first {
        "hourly" => {
            let minute = minute_anchor(&mut w)?.unwrap_or(0);
            w.finish()?;
            Ok(format!("{minute} * * * *"))
        }
        "daily" => daily(&mut w),
        "weekly" => weekly(&mut w, None),
        "every" => {
            let Some(next) = w.peek() else {
                return Err("expected an interval, `day`, `week` or a weekday after `every`".to_owned());
            };
            if next == "day" {
                w.take();
                daily(&mut w)
            } else if next == "week" {
                w.take();
                weekly(&mut w, None)
            } else if let Some(day) = weekday(next) {
                w.take();
                weekly(&mut w, Some(day))
            } else {
                interval(&mut w)
            }
        }
        other => Err(format!(
            "`{other}` does not start a schedule; use hourly, daily, weekly or `every ...`"
        )),
    }
}

fn daily(w: &mut Words<'_>) -> Result<String, String> {
    let (h, m) = at_time(w)?.unwrap_or((0, 0));
    w.finish()?;
    Ok(format!("{m} {h} * * *"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn text_grammar_covers_the_documented_table() {
        for (text, cron) in [
            ("every 30 minutes", "*/30 * * * *"),
            ("Every 15 minutes starting at :07", "7-59/15 * * * *"),
            ("hourly", "0 * * * *"),
            ("every 2 hours", "0 */2 * * *"),
            ("daily", "0 0 * * *"),
            ("daily at 9:00", "0 9 * * *"),
            ("daily at 9am", "0 9 * * *"),
            ("daily at 5:30 PM", "30 17 * * *"),
            ("weekly", "0 0 * * 0"),
        ] {
            assert_eq!(text_to_cron(text).as_deref(), Ok(cron), "{text}");
        }
    }
}
