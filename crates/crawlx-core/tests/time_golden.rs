//! Golden tests of the time facade: every text the former `chrono` types wrote or accepted is
//! pinned as a literal, so the wire formats (JSON, RFC 3339, `Display`) cannot drift. The tables
//! were generated from chrono 0.4.45 before it was removed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::type_complexity)]

use crawlx_core::extraction::ArticleDateV1;
use crawlx_core::orchestration::RecrawlBaselineV1;
use crawlx_core::time::{Duration, FixedDateTime, NaiveDate, SecondsFormat, Timestamp};

/// `(unix seconds, nanoseconds, JSON, to_rfc3339(), Secs/Z, Millis/Z, Micros/Z, Nanos/Z, AutoSi/+00:00, Display, Debug)`.
pub const TIMESTAMPS: &[(i64, u32, &str, &str, &str, &str, &str, &str, &str, &str, &str)] = &[
    (0, 0, "\"1970-01-01T00:00:00Z\"", "1970-01-01T00:00:00+00:00", "1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000Z", "1970-01-01T00:00:00.000000Z", "1970-01-01T00:00:00.000000000Z", "1970-01-01T00:00:00+00:00", "1970-01-01 00:00:00 UTC", "1970-01-01T00:00:00Z"),
    (1700000000, 0, "\"2023-11-14T22:13:20Z\"", "2023-11-14T22:13:20+00:00", "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.000Z", "2023-11-14T22:13:20.000000Z", "2023-11-14T22:13:20.000000000Z", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20 UTC", "2023-11-14T22:13:20Z"),
    (1700000000, 120000000, "\"2023-11-14T22:13:20.120Z\"", "2023-11-14T22:13:20.120+00:00", "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.120Z", "2023-11-14T22:13:20.120000Z", "2023-11-14T22:13:20.120000000Z", "2023-11-14T22:13:20.120+00:00", "2023-11-14 22:13:20.120 UTC", "2023-11-14T22:13:20.120Z"),
    (1700000000, 123000000, "\"2023-11-14T22:13:20.123Z\"", "2023-11-14T22:13:20.123+00:00", "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20.123000Z", "2023-11-14T22:13:20.123000000Z", "2023-11-14T22:13:20.123+00:00", "2023-11-14 22:13:20.123 UTC", "2023-11-14T22:13:20.123Z"),
    (1700000000, 123400000, "\"2023-11-14T22:13:20.123400Z\"", "2023-11-14T22:13:20.123400+00:00", "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20.123400Z", "2023-11-14T22:13:20.123400000Z", "2023-11-14T22:13:20.123400+00:00", "2023-11-14 22:13:20.123400 UTC", "2023-11-14T22:13:20.123400Z"),
    (1700000000, 123456000, "\"2023-11-14T22:13:20.123456Z\"", "2023-11-14T22:13:20.123456+00:00", "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20.123456Z", "2023-11-14T22:13:20.123456000Z", "2023-11-14T22:13:20.123456+00:00", "2023-11-14 22:13:20.123456 UTC", "2023-11-14T22:13:20.123456Z"),
    (1700000000, 123456700, "\"2023-11-14T22:13:20.123456700Z\"", "2023-11-14T22:13:20.123456700+00:00", "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20.123456Z", "2023-11-14T22:13:20.123456700Z", "2023-11-14T22:13:20.123456700+00:00", "2023-11-14 22:13:20.123456700 UTC", "2023-11-14T22:13:20.123456700Z"),
    (1700000000, 123456789, "\"2023-11-14T22:13:20.123456789Z\"", "2023-11-14T22:13:20.123456789+00:00", "2023-11-14T22:13:20Z", "2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20.123456Z", "2023-11-14T22:13:20.123456789Z", "2023-11-14T22:13:20.123456789+00:00", "2023-11-14 22:13:20.123456789 UTC", "2023-11-14T22:13:20.123456789Z"),
    (-1, 999999999, "\"1969-12-31T23:59:59.999999999Z\"", "1969-12-31T23:59:59.999999999+00:00", "1969-12-31T23:59:59Z", "1969-12-31T23:59:59.999Z", "1969-12-31T23:59:59.999999Z", "1969-12-31T23:59:59.999999999Z", "1969-12-31T23:59:59.999999999+00:00", "1969-12-31 23:59:59.999999999 UTC", "1969-12-31T23:59:59.999999999Z"),
    (-62135596800, 0, "\"0001-01-01T00:00:00Z\"", "0001-01-01T00:00:00+00:00", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z", "0001-01-01T00:00:00.000000Z", "0001-01-01T00:00:00.000000000Z", "0001-01-01T00:00:00+00:00", "0001-01-01 00:00:00 UTC", "0001-01-01T00:00:00Z"),
    (253402300799, 999999000, "\"9999-12-31T23:59:59.999999Z\"", "9999-12-31T23:59:59.999999+00:00", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59.999Z", "9999-12-31T23:59:59.999999Z", "9999-12-31T23:59:59.999999000Z", "9999-12-31T23:59:59.999999+00:00", "9999-12-31 23:59:59.999999 UTC", "9999-12-31T23:59:59.999999Z"),
    (4102444800, 1000000, "\"2100-01-01T00:00:00.001Z\"", "2100-01-01T00:00:00.001+00:00", "2100-01-01T00:00:00Z", "2100-01-01T00:00:00.001Z", "2100-01-01T00:00:00.001000Z", "2100-01-01T00:00:00.001000000Z", "2100-01-01T00:00:00.001+00:00", "2100-01-01 00:00:00.001 UTC", "2100-01-01T00:00:00.001Z"),
    (951782400, 0, "\"2000-02-29T00:00:00Z\"", "2000-02-29T00:00:00+00:00", "2000-02-29T00:00:00Z", "2000-02-29T00:00:00.000Z", "2000-02-29T00:00:00.000000Z", "2000-02-29T00:00:00.000000000Z", "2000-02-29T00:00:00+00:00", "2000-02-29 00:00:00 UTC", "2000-02-29T00:00:00Z"),
    (1709164800, 500000000, "\"2024-02-29T00:00:00.500Z\"", "2024-02-29T00:00:00.500+00:00", "2024-02-29T00:00:00Z", "2024-02-29T00:00:00.500Z", "2024-02-29T00:00:00.500000Z", "2024-02-29T00:00:00.500000000Z", "2024-02-29T00:00:00.500+00:00", "2024-02-29 00:00:00.500 UTC", "2024-02-29T00:00:00.500Z"),
];
/// `(input, instant as unix seconds + nanoseconds + offset seconds + to_rfc3339(), or None when rejected)`.
pub const RFC3339_INPUTS: &[(&str, Option<(i64, u32, i32, &str)>)] = &[
    ("2026-11-04T12:34:56Z", Some((1793795696, 0, 0, "2026-11-04T12:34:56+00:00"))),
    ("2026-11-04T12:34:56.5+02:00", Some((1793788496, 500000000, 7200, "2026-11-04T12:34:56.500+02:00"))),
    ("2026-11-04 12:34:56-05:30", Some((1793815496, 0, -19800, "2026-11-04T12:34:56-05:30"))),
    ("2026-11-04t12:34:56.123456789123z", Some((1793795696, 123456789, 0, "2026-11-04T12:34:56.123456789+00:00"))),
    ("2026-11-04T12:34:56", None),
    ("2026-02-30T00:00:00Z", None),
    ("2026-11-04T24:00:00Z", None),
    ("2026-11-04T12:34:56+24:00", None),
    ("20261104T123456Z", None),
    ("2026-11-04T12:34:56 Z", None),
    ("+12345-01-01T00:00:00Z", None),
];
/// `(input, parsed with the relaxed reader used by serde, to_rfc3339(), or None)`.
pub const RELAXED_INPUTS: &[(&str, Option<&str>)] = &[
    ("2026-11-04T12:34:56Z", Some("2026-11-04T12:34:56+00:00")),
    ("2026-1-4 2:3:4 +0200", Some("2026-01-04T02:03:04+02:00")),
    ("2026-11-04T12:34:56 UTC", Some("2026-11-04T12:34:56+00:00")),
    ("2026 - 11 - 04 T 12 : 34 : 56 . 5 Z", None),
    ("2026-11-04", None),
    ("garbage", None),
    ("2026-11-04T12:34:56.1234567891Z", Some("2026-11-04T12:34:56.123456789+00:00")),
    ("-0001-01-01T00:00:00Z", Some("-0001-01-01T00:00:00+00:00")),
];
/// `(input, JSON of the date, or None when rejected)` for `YYYY-MM-DD` dates.
pub const DATES: &[(&str, Option<&str>)] = &[
    ("2026-11-04", Some("\"2026-11-04\"")),
    ("2024-02-29", Some("\"2024-02-29\"")),
    ("2026-02-29", None),
    ("0001-01-01", Some("\"0001-01-01\"")),
    ("9999-12-31", Some("\"9999-12-31\"")),
    (" 2026-1-4", Some("\"2026-01-04\"")),
    ("2026-11-04 ", Some("\"2026-11-04\"")),
    ("+12345-06-07", Some("\"+12345-06-07\"")),
    ("-0001-01-01", Some("\"-0001-01-01\"")),
    ("2026/11/04", None),
];
/// `(RFC 2822 input, unix seconds, offset seconds, to_rfc3339(), or None when rejected)`.
pub const RFC2822_INPUTS: &[(&str, Option<(i64, i32, &str)>)] = &[
    ("Tue, 1 Jul 2003 10:52:37 +0200", Some((1057049557, 7200, "2003-07-01T10:52:37+02:00"))),
    ("Sun, 06 Nov 1994 08:49:37 GMT", Some((784111777, 0, "1994-11-06T08:49:37+00:00"))),
    ("Mon, 06 Nov 1994 08:49:37 GMT", None),
    ("4 Nov 26 12:34 EST", Some((1793813640, -18000, "2026-11-04T12:34:00-05:00"))),
    ("Wed, 4 Nov 2026 12:34:56 -0000 (UTC)", Some((1793795696, 0, "2026-11-04T12:34:56+00:00"))),
    ("Thu, 01 Jan 1970 00:00:00 Z", Some((0, 0, "1970-01-01T00:00:00+00:00"))),
    ("Sun, 06 Nov 1994 08:49:37", None),
    ("garbage", None),
];

#[test]
fn timestamp_text_forms_match_the_former_chrono_output() {
    for &(secs, nanos, json, rfc3339, secs_z, millis_z, micros_z, nanos_z, auto_plus, display, debug) in TIMESTAMPS {
        let ts = Timestamp::from_timestamp(secs, nanos).unwrap();
        assert_eq!(serde_json::to_string(&ts).unwrap(), json, "json {secs} {nanos}");
        assert_eq!(serde_json::from_str::<Timestamp>(json).unwrap(), ts, "round trip {json}");
        assert_eq!(ts.to_rfc3339(), rfc3339);
        assert_eq!(ts.to_rfc3339_opts(SecondsFormat::Secs, true), secs_z);
        assert_eq!(ts.to_rfc3339_opts(SecondsFormat::Millis, true), millis_z);
        assert_eq!(ts.to_rfc3339_opts(SecondsFormat::Micros, true), micros_z);
        assert_eq!(ts.to_rfc3339_opts(SecondsFormat::Nanos, true), nanos_z);
        assert_eq!(ts.to_rfc3339_opts(SecondsFormat::AutoSi, false), auto_plus);
        assert_eq!(ts.to_string(), display);
        assert_eq!(format!("{ts:?}"), debug);
        assert_eq!((ts.timestamp(), ts.timestamp_subsec_nanos()), (secs, nanos));
    }
}

#[test]
fn rfc3339_reader_accepts_and_rejects_what_chrono_did() {
    for &(input, expected) in RFC3339_INPUTS {
        match (FixedDateTime::parse_rfc3339(input), expected) {
            (Ok(parsed), Some((secs, nanos, offset, text))) => {
                assert_eq!(parsed.to_utc().timestamp(), secs, "{input}");
                assert_eq!(parsed.to_utc().timestamp_subsec_nanos(), nanos, "{input}");
                assert_eq!(parsed.offset_seconds(), offset, "{input}");
                assert_eq!(parsed.to_rfc3339(), text, "{input}");
            }
            (Err(_), None) => {}
            (got, want) => panic!("{input}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn relaxed_reader_matches_chrono_from_str() {
    for &(input, expected) in RELAXED_INPUTS {
        match (input.parse::<FixedDateTime>(), expected) {
            (Ok(parsed), Some(text)) => assert_eq!(parsed.to_rfc3339(), text, "{input}"),
            (Err(_), None) => {}
            (got, want) => panic!("{input}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn rfc2822_reader_matches_chrono() {
    for &(input, expected) in RFC2822_INPUTS {
        match (FixedDateTime::parse_rfc2822(input), expected) {
            (Ok(parsed), Some((secs, offset, text))) => {
                assert_eq!(parsed.to_utc().timestamp(), secs, "{input}");
                assert_eq!(parsed.offset_seconds(), offset, "{input}");
                assert_eq!(parsed.to_rfc3339(), text, "{input}");
            }
            (Err(_), None) => {}
            (got, want) => panic!("{input}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn calendar_dates_serialize_and_parse_like_chrono() {
    for &(input, expected) in DATES {
        match (input.parse::<NaiveDate>(), expected) {
            (Ok(date), Some(json)) => {
                assert_eq!(serde_json::to_string(&date).unwrap(), json, "{input}");
                assert_eq!(serde_json::from_str::<NaiveDate>(json).unwrap(), date);
            }
            (Err(_), None) => {}
            (got, want) => panic!("{input}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn persisted_types_keep_their_json_shape() {
    let observed = Timestamp::from_timestamp(1_700_000_000, 120_000_000).unwrap();
    let baseline = RecrawlBaselineV1::new(None, observed, 1000);
    let json = serde_json::to_value(&baseline).unwrap();
    assert_eq!(json["observedAt"], "2023-11-14T22:13:20.120Z");
    let back: RecrawlBaselineV1 = serde_json::from_value(json).unwrap();
    assert_eq!(back, baseline);

    let article = ArticleDateV1::new(NaiveDate::from_ymd_opt(2026, 11, 2).unwrap(), Some("2026-11-02T09:30:00+01:00".into()));
    assert_eq!(
        serde_json::to_string(&article).unwrap(),
        r#"{"date":"2026-11-02","timestamp":"2026-11-02T09:30:00+01:00"}"#
    );
}

#[test]
fn database_forms_of_a_timestamp_are_unchanged() {
    // SQLite and the audit chain store whole microseconds since the epoch; MariaDB gets a
    // `DATETIME(6)` literal; PostgreSQL a `timestamptz` RFC 3339 literal with microseconds.
    let ts = Timestamp::from_timestamp(1_700_000_000, 123_456_789).unwrap();
    assert_eq!(ts.timestamp_micros(), 1_700_000_000_123_456);
    assert_eq!(ts.to_rfc3339_opts(SecondsFormat::Micros, true), "2023-11-14T22:13:20.123456Z");
    assert_eq!(Timestamp::from_timestamp_micros(1_700_000_000_123_456).unwrap().timestamp_subsec_nanos(), 123_456_000);
    let negative = Timestamp::from_timestamp(-1, 999_999_999).unwrap();
    assert_eq!(negative.timestamp_micros(), -1);
    assert_eq!(negative.timestamp_millis(), -1);
}

#[test]
fn durations_keep_their_arithmetic() {
    let t = Timestamp::from_timestamp(1_700_000_000, 0).unwrap();
    assert_eq!((t + Duration::hours(1) - t).num_seconds(), 3600);
    assert_eq!(Duration::milliseconds(1500).num_milliseconds(), 1500);
    assert_eq!(Duration::seconds(-90).to_string(), "-PT90S");
    assert_eq!(Duration::milliseconds(1500).to_string(), "PT1.5S");
    assert_eq!(Duration::zero().to_string(), "P0D");
    assert!(Duration::seconds(-1).to_std().is_err());
    assert_eq!(Duration::from_std(std::time::Duration::from_millis(250)).unwrap(), Duration::milliseconds(250));
    assert!(t.checked_add_signed(Duration::MAX).is_none());
}
