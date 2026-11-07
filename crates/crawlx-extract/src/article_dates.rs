//! Bounded Gregorian date rules using only caller-supplied locale, zone and reference date.
//! Month names and digit ranges are independently authored facts, not a downloaded lexicon.

use chrono::{DateTime, Datelike, FixedOffset, LocalResult, NaiveDate, NaiveDateTime, TimeZone};
use crawlx_core::extraction::{ArticleDateV1, ExtractionPolicyV1};

enum Zone {
    Fixed(FixedOffset),
    Named(chrono_tz::Tz),
}
fn zone(raw: &str) -> Option<Zone> {
    if matches!(raw, "Z" | "UTC") {
        return FixedOffset::east_opt(0).map(Zone::Fixed);
    }
    let bytes = raw.as_bytes();
    if bytes.len() == 6 && matches!(bytes[0], b'+' | b'-') && bytes[3] == b':' {
        if !bytes[1..3].iter().chain(&bytes[4..6]).all(u8::is_ascii_digit) {
            return None;
        }
        let hours = raw.get(1..3)?.parse::<i32>().ok()?;
        let minutes = raw.get(4..6)?.parse::<i32>().ok()?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        let seconds = (hours * 3600 + minutes * 60) * if bytes[0] == b'-' { -1 } else { 1 };
        return FixedOffset::east_opt(seconds).map(Zone::Fixed);
    }
    raw.parse().ok().map(Zone::Named)
}
pub(crate) fn validate_timezone(policy: &ExtractionPolicyV1) -> Result<(), crate::ExtractError> {
    if policy
        .date_timezone
        .as_deref()
        .is_some_and(|value| zone(value).is_none())
    {
        return Err(crawlx_core::CoreError::Invalid {
            field: "extract.content.dateTimezone",
            reason: "unknown IANA timezone or invalid fixed offset".into(),
        }
        .into());
    }
    Ok(())
}
fn digits(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            let value = u32::from(ch);
            for base in [0x0660, 0x06f0, 0x0966, 0x09e6, 0x0e50] {
                if (base..base + 10).contains(&value) {
                    return char::from_u32(u32::from(b'0') + value - base).unwrap_or(ch);
                }
            }
            ch
        })
        .collect()
}
fn month(raw: &str, language: &str) -> Option<u32> {
    let names: &[&[&str]] = match language {
        "fr" => &[
            &["janvier", "janv"],
            &["février", "févr"],
            &["mars"],
            &["avril", "avr"],
            &["mai"],
            &["juin"],
            &["juillet", "juil"],
            &["août"],
            &["septembre", "sept"],
            &["octobre", "oct"],
            &["novembre", "nov"],
            &["décembre", "déc"],
        ],
        "de" => &[
            &["januar", "jan"],
            &["februar", "feb"],
            &["märz", "mär"],
            &["april", "apr"],
            &["mai"],
            &["juni", "jun"],
            &["juli", "jul"],
            &["august", "aug"],
            &["september", "sep"],
            &["oktober", "okt"],
            &["november", "nov"],
            &["dezember", "dez"],
        ],
        "es" => &[
            &["enero", "ene"],
            &["febrero", "feb"],
            &["marzo", "mar"],
            &["abril", "abr"],
            &["mayo", "may"],
            &["junio", "jun"],
            &["julio", "jul"],
            &["agosto", "ago"],
            &["septiembre", "sep"],
            &["octubre", "oct"],
            &["noviembre", "nov"],
            &["diciembre", "dic"],
        ],
        "" | "en" => &[
            &["january", "jan"],
            &["february", "feb"],
            &["march", "mar"],
            &["april", "apr"],
            &["may"],
            &["june", "jun"],
            &["july", "jul"],
            &["august", "aug"],
            &["september", "sep"],
            &["october", "oct"],
            &["november", "nov"],
            &["december", "dec"],
        ],
        _ => return None,
    };
    names
        .iter()
        .position(|items| items.contains(&raw))
        .and_then(|i| u32::try_from(i + 1).ok())
}
fn full_year_prefix(raw: &str) -> bool {
    raw.as_bytes()
        .get(..4)
        .is_some_and(|year| year.iter().all(u8::is_ascii_digit))
        && raw
            .get(4..)
            .is_some_and(|tail| tail.starts_with(['-', '/', '年']))
}
/// Selected date plus uncertainty caused by explicit two-digit-year inference.
pub(crate) fn parse(raw: &str, policy: &ExtractionPolicyV1) -> Option<(ArticleDateV1, bool)> {
    if raw.len() > 4096 {
        return None;
    }
    let normalized = digits(raw.trim());
    let raw = normalized.as_str();
    if let Ok(value) = DateTime::parse_from_rfc3339(raw).or_else(|_| DateTime::parse_from_rfc2822(raw)) {
        return finish(value.date_naive(), Some(value.to_rfc3339()), false, policy);
    }
    for format in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Some(local) = full_year_prefix(raw)
            .then(|| NaiveDateTime::parse_from_str(raw, format).ok())
            .flatten()
        {
            let utc = match zone(policy.date_timezone.as_deref()?)? {
                Zone::Fixed(zone) => match zone.from_local_datetime(&local) {
                    LocalResult::Single(value) => value.to_rfc3339(),
                    _ => return None,
                },
                Zone::Named(zone) => match zone.from_local_datetime(&local) {
                    LocalResult::Single(value) => value.to_rfc3339(),
                    _ => return None,
                },
            };
            return finish(local.date(), Some(utc), false, policy);
        }
    }
    let locale = policy
        .locale
        .as_deref()
        .unwrap_or("")
        .replace('_', "-")
        .to_ascii_lowercase();
    let language = locale.split('-').next().unwrap_or("");
    let lower = raw.to_lowercase();
    let relative = match (language, lower.as_str()) {
        ("en", "today") | ("fr", "aujourd’hui" | "aujourd'hui") | ("de", "heute") | ("es", "hoy") => {
            Some(0)
        }
        ("en", "yesterday") | ("fr", "hier") | ("de", "gestern") | ("es", "ayer") => Some(1),
        _ => None,
    };
    if let Some(days) = relative {
        return finish(
            policy
                .reference_date?
                .checked_sub_signed(chrono::Duration::days(days))?,
            None,
            true,
            policy,
        );
    }
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y年%m月%d日"] {
        if let Some(value) = full_year_prefix(raw)
            .then(|| NaiveDate::parse_from_str(raw, format).ok())
            .flatten()
        {
            return finish(value, None, false, policy);
        }
    }
    let parts: Vec<_> = lower
        .split(|c: char| c.is_whitespace() || matches!(c, '/' | '-' | '.' | ','))
        .filter(|s| !s.is_empty() && *s != "de")
        .take(5)
        .collect();
    if parts.len() != 3 {
        return None;
    }
    let year_raw = parts[2];
    let mut year = year_raw.parse::<i32>().ok()?;
    let inferred = year_raw.len() == 2;
    if inferred {
        let reference = policy.reference_date?;
        year += reference.year().div_euclid(100) * 100;
        if year > reference.year() {
            year -= 100;
        }
    } else if year_raw.len() != 4 {
        return None;
    }
    let pair = if let Some(month) = month(parts[0], language) {
        Some((month, parts[1].parse().ok()?))
    } else if let Some(month) = month(parts[1], language) {
        Some((month, parts[0].parse().ok()?))
    } else {
        let first = parts[0].parse::<u32>().ok()?;
        let second = parts[1].parse::<u32>().ok()?;
        let region = locale.split('-').nth(1);
        if matches!(region, Some("us" | "ph")) || second > 12 {
            Some((first, second))
        } else if matches!(
            region,
            Some("gb" | "fr" | "de" | "es" | "in" | "au" | "nz" | "ie" | "za")
        ) || first > 12
        {
            Some((second, first))
        } else if first == second {
            Some((first, second))
        } else {
            None
        }
    }?;
    finish(
        NaiveDate::from_ymd_opt(year, pair.0, pair.1)?,
        None,
        inferred,
        policy,
    )
}
fn finish(
    date: NaiveDate,
    timestamp: Option<String>,
    uncertain: bool,
    policy: &ExtractionPolicyV1,
) -> Option<(ArticleDateV1, bool)> {
    policy
        .reference_date
        .is_none_or(|reference| date <= reference)
        .then(|| (ArticleDateV1::new(date, timestamp), uncertain))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn caller_locale_digits_and_ambiguity() {
        let mut policy = ExtractionPolicyV1::default();
        policy.reference_date = NaiveDate::from_ymd_opt(2026, 11, 2);
        assert!(parse("03/04/2025", &policy).is_none());
        for (locale, input, expected) in [
            ("fr-FR", "4 février 2025", "2025-02-04"),
            ("de-DE", "4. März 2025", "2025-03-04"),
            ("es-ES", "4 de mayo de 2025", "2025-05-04"),
            ("en-GB", "०४/०३/२०२५", "2025-03-04"),
            ("en-US", "04/03/2025", "2025-04-03"),
        ] {
            policy.locale = Some(locale.into());
            assert_eq!(parse(input, &policy).unwrap().0.date.to_string(), expected);
        }
        let (date, inferred) = parse("04/03/25", &policy).unwrap();
        assert_eq!(date.date.to_string(), "2025-04-03");
        assert!(inferred);
        policy.reference_date = None;
        assert!(parse("04/03/25", &policy).is_none());
        assert!(parse("25-03-04T12:00:00", &policy).is_none());
        policy.reference_date = NaiveDate::from_ymd_opt(2026, 11, 2);
        policy.locale = Some("fr-FR".into());
        assert!(parse("hier", &policy).unwrap().1);
    }
    #[test]
    fn explicit_zone_rejects_gap_and_fold_without_inventing_midnight() {
        let mut policy = ExtractionPolicyV1::default();
        policy.date_timezone = Some("America/New_York".into());
        assert!(parse("2025-03-09T02:30:00", &policy).is_none());
        assert!(parse("2025-11-02T01:30:00", &policy).is_none());
        assert!(parse("2025-02-04T12:30:00", &policy)
            .unwrap()
            .0
            .timestamp
            .unwrap()
            .ends_with("-05:00"));
        assert!(parse("2025-02-04", &policy).unwrap().0.timestamp.is_none());
        policy.date_timezone = Some("Not/AZone".into());
        assert!(validate_timezone(&policy).is_err());
    }
}
