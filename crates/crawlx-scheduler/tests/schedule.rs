//! `Schedule`: the cron/text grammar, zones and DST, the 5-minute floor, determinism and the
//! serde round trip of the request form.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Utc};
use crawlx_scheduler::schedule::{Schedule, ScheduleError, ScheduleSpec, MIN_INTERVAL_SECS};
use serde_json::json;

fn utc(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn text(t: &str, tz: &str) -> ScheduleSpec {
    ScheduleSpec {
        cron: None,
        text: Some(t.to_owned()),
        timezone: Some(tz.to_owned()),
    }
}

fn cron(c: &str, tz: &str) -> ScheduleSpec {
    ScheduleSpec {
        cron: Some(c.to_owned()),
        text: None,
        timezone: Some(tz.to_owned()),
    }
}

/// Every occurrence in `[from, to)`.
fn occurrences(s: &Schedule, from: &str, to: &str) -> Vec<DateTime<Utc>> {
    let end = utc(to);
    let mut out = Vec::new();
    let mut at = utc(from);
    while let Some(next) = s.next_after(at) {
        if next >= end {
            break;
        }
        out.push(next);
        at = next;
    }
    out
}

#[test]
fn natural_text_grammar_table() {
    let table = [
        ("every 30 minutes", "*/30 * * * *"),
        ("Every 15 minutes starting at :07", "7-59/15 * * * *"),
        ("every 15 minutes at :07", "7-59/15 * * * *"),
        ("every 5 minutes", "*/5 * * * *"),
        ("every 45 mins", "*/45 * * * *"),
        ("hourly", "0 * * * *"),
        ("HOURLY at :15", "15 * * * *"),
        ("every hour", "0 * * * *"),
        ("every 60 minutes", "0 * * * *"),
        ("every 2 hours", "0 */2 * * *"),
        ("every 6 hrs starting at :30", "30 */6 * * *"),
        ("every 120 minutes", "0 */2 * * *"),
        ("every 24 hours", "0 0 * * *"),
        ("daily", "0 0 * * *"),
        ("every day", "0 0 * * *"),
        ("daily at 9:00", "0 9 * * *"),
        ("daily at 9am", "0 9 * * *"),
        ("daily at 9 am", "0 9 * * *"),
        ("  daily   at 5:30 PM ", "30 17 * * *"),
        ("daily at 12am", "0 0 * * *"),
        ("daily at 12pm", "0 12 * * *"),
        ("daily at 17:45", "45 17 * * *"),
        ("daily at noon", "0 12 * * *"),
        ("daily at midnight", "0 0 * * *"),
        ("every day at 7am", "0 7 * * *"),
        ("weekly", "0 0 * * 0"),
        ("weekly on friday", "0 0 * * 5"),
        ("weekly on mon at 8:15am", "15 8 * * 1"),
        ("every week on tuesday", "0 0 * * 2"),
        ("every monday at 9am", "0 9 * * 1"),
        ("every sat", "0 0 * * 6"),
    ];
    for (input, expected) in table {
        let s = Schedule::parse(&text(input, "UTC")).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!(s.cron(), expected, "{input:?}");
        assert_eq!(s.timezone(), "UTC");
    }
}

#[test]
fn cron_expressions_are_normalized_and_validated() {
    let s = Schedule::parse(&cron("  */30   *  * * *  ", "UTC")).unwrap();
    assert_eq!(s.cron(), "*/30 * * * *");
    for ok in [
        "7-59/15 * * * *",
        "0 9 * * mon-fri",
        "0,30 8-18 * * 1-5",
        "0 0 1 * *",
        "*/5 * * * *",
        "0 0 29 2 *",
    ] {
        Schedule::parse(&cron(ok, "UTC")).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
    }
    for bad in [
        "* * * *",
        "* * * * * *",
        "0 0 * * * 2025",
        "@daily",
        "61 * * * *",
        "0 25 * * *",
        "0 0 32 * *",
        "banana * * * *",
        "",
    ] {
        let e = Schedule::parse(&cron(bad, "UTC")).unwrap_err();
        assert!(matches!(e, ScheduleError::InvalidCron { .. }), "{bad:?} -> {e:?}");
        assert_eq!(e.field(), "cron");
        assert_eq!(e.code(), "invalid");
    }
}

#[test]
fn text_outside_the_grammar_is_a_typed_error() {
    for bad in [
        "",
        "   ",
        "yearly",
        "monthly",
        "every banana",
        "every",
        "every 0 minutes",
        "every 90 minutes",
        "every 25 hours",
        "every 2 days",
        "daily at",
        "daily at 25:00",
        "daily at 9:5",
        "daily at 13pm",
        "daily at 0am",
        "daily at nine",
        "daily at 9am sharp",
        "weekly on someday",
        "weekly on",
        "hourly at 15",
        "hourly at :75",
        "every 15 minutes starting :07",
        "every 15 minutes starting at 07",
        "run it daily",
        "every 30 minutes until noon",
    ] {
        let e = Schedule::parse(&text(bad, "UTC")).unwrap_err();
        assert!(matches!(e, ScheduleError::InvalidText { .. }), "{bad:?} -> {e:?}");
        assert_eq!(e.field(), "text");
        assert!(e.to_string().contains("unsupported schedule text"), "{e}");
    }
}

#[test]
fn exactly_one_of_cron_and_text_and_a_known_zone() {
    assert_eq!(
        Schedule::parse(&ScheduleSpec::default()).unwrap_err(),
        ScheduleError::Missing
    );
    let both = ScheduleSpec {
        cron: Some("0 * * * *".to_owned()),
        text: Some("hourly".to_owned()),
        timezone: None,
    };
    assert_eq!(Schedule::parse(&both).unwrap_err(), ScheduleError::Ambiguous);
    assert_eq!(ScheduleError::Missing.code(), "required");
    for bad_zone in ["Mars/Olympus", "", "utc+2", "Europe/Atlantis"] {
        let e = Schedule::parse(&text("hourly", bad_zone)).unwrap_err();
        assert_eq!(e, ScheduleError::UnknownTimezone(bad_zone.to_owned()));
        assert_eq!(e.field(), "timezone");
    }
    // the zone defaults to UTC
    let s = Schedule::parse(&ScheduleSpec {
        cron: None,
        text: Some("hourly".to_owned()),
        timezone: None,
    })
    .unwrap();
    assert_eq!(s.timezone(), "UTC");
}

#[test]
fn schedules_faster_than_five_minutes_are_rejected() {
    for (spec, gap) in [
        (cron("* * * * *", "UTC"), 60),
        (cron("*/4 * * * *", "UTC"), 240),
        (cron("*/1 * * * *", "UTC"), 60),
        (cron("0,3 * * * *", "UTC"), 180),
        (cron("0 0 1 * *", "UTC"), 0),
        (text("every minute", "UTC"), 60),
        (text("every 1 minute", "UTC"), 60),
        (text("every 3 minutes", "UTC"), 180),
        (text("every 4 minutes", "UTC"), 240),
        // 0, 7, ... 56 then 0: the gap across the hour boundary is 4 minutes
        (text("every 7 minutes", "UTC"), 240),
        // a dense first-of-month burst is found too
        (cron("0,2 * 1 * *", "UTC"), 120),
    ] {
        let result = Schedule::parse(&spec);
        if gap == 0 {
            // a once-a-month schedule is fine
            assert!(result.is_ok(), "{spec:?}");
            continue;
        }
        match result.unwrap_err() {
            ScheduleError::TooFrequent { min_gap_secs } => assert_eq!(min_gap_secs, gap, "{spec:?}"),
            other => panic!("{spec:?} -> {other:?}"),
        }
    }
    assert_eq!(MIN_INTERVAL_SECS, 300);
    let e = Schedule::parse(&text("every 3 minutes", "UTC")).unwrap_err();
    assert_eq!(e.code(), "too_frequent");
    // the boundary itself is allowed
    for ok in ["every 5 minutes", "every 10 minutes", "every 45 minutes"] {
        Schedule::parse(&text(ok, "UTC")).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
}

#[test]
fn next_after_walks_a_cron_series_in_utc() {
    let s = Schedule::parse(&cron("7-59/15 * * * *", "UTC")).unwrap();
    let got = occurrences(&s, "2025-06-01T10:00:00Z", "2025-06-01T12:00:00Z");
    let want: Vec<_> = [
        "2025-06-01T10:07:00Z",
        "2025-06-01T10:22:00Z",
        "2025-06-01T10:37:00Z",
        "2025-06-01T10:52:00Z",
        "2025-06-01T11:07:00Z",
        "2025-06-01T11:22:00Z",
        "2025-06-01T11:37:00Z",
        "2025-06-01T11:52:00Z",
    ]
    .into_iter()
    .map(utc)
    .collect();
    assert_eq!(got, want);
    // strictly after: an exact occurrence yields the following one
    assert_eq!(
        s.next_after(utc("2025-06-01T10:07:00Z")),
        Some(utc("2025-06-01T10:22:00Z"))
    );
    assert_eq!(
        s.next_after(utc("2025-06-01T10:06:59Z")),
        Some(utc("2025-06-01T10:07:00Z"))
    );
}

#[test]
fn daily_text_follows_the_wall_clock_of_the_zone() {
    // Asia/Kolkata is UTC+5:30 without DST
    let s = Schedule::parse(&text("daily at 9am", "Asia/Kolkata")).unwrap();
    assert_eq!(s.cron(), "0 9 * * *");
    assert_eq!(s.timezone(), "Asia/Kolkata");
    assert_eq!(
        s.next_after(utc("2025-01-01T00:00:00Z")),
        Some(utc("2025-01-01T03:30:00Z"))
    );
    assert_eq!(
        s.next_after(utc("2025-01-01T03:30:00Z")),
        Some(utc("2025-01-02T03:30:00Z"))
    );
    // the same text in New York in winter (UTC-5)
    let ny = Schedule::parse(&text("daily at 9am", "America/New_York")).unwrap();
    assert_eq!(
        ny.next_after(utc("2025-01-15T00:00:00Z")),
        Some(utc("2025-01-15T14:00:00Z"))
    );
    // and in summer (UTC-4)
    assert_eq!(
        ny.next_after(utc("2025-07-15T00:00:00Z")),
        Some(utc("2025-07-15T13:00:00Z"))
    );
}

#[test]
fn a_daily_0230_job_fires_once_on_the_spring_forward_day() {
    // America/New_York 2025-03-09: 02:00 EST jumps to 03:00 EDT, so 02:30 does not exist
    let s = Schedule::parse(&cron("30 2 * * *", "America/New_York")).unwrap();
    let got = occurrences(&s, "2025-03-07T12:00:00Z", "2025-03-12T00:00:00Z");
    assert_eq!(
        got,
        vec![
            utc("2025-03-08T07:30:00Z"), // 02:30 EST
            utc("2025-03-09T07:00:00Z"), // gap day: fires once, at 03:00 EDT
            utc("2025-03-10T06:30:00Z"), // 02:30 EDT
            utc("2025-03-11T06:30:00Z"),
        ]
    );
    // the text form behaves the same
    let t = Schedule::parse(&text("daily at 2:30 am", "America/New_York")).unwrap();
    assert_eq!(
        occurrences(&t, "2025-03-07T12:00:00Z", "2025-03-12T00:00:00Z"),
        got
    );
    // Europe/Berlin 2025-03-30: 02:00 CET jumps to 03:00 CEST
    let berlin = Schedule::parse(&cron("30 2 * * *", "Europe/Berlin")).unwrap();
    assert_eq!(
        occurrences(&berlin, "2025-03-29T12:00:00Z", "2025-04-01T12:00:00Z"),
        vec![
            utc("2025-03-30T01:00:00Z"), // 03:00 CEST
            utc("2025-03-31T00:30:00Z"), // 02:30 CEST
            utc("2025-04-01T00:30:00Z"),
        ]
    );
}

#[test]
fn a_fixed_time_job_fires_once_on_the_fall_back_day() {
    // America/New_York 2025-11-02: 02:00 EDT falls back to 01:00 EST, so 01:30 happens twice
    let s = Schedule::parse(&cron("30 1 * * *", "America/New_York")).unwrap();
    assert_eq!(
        occurrences(&s, "2025-10-31T12:00:00Z", "2025-11-04T00:00:00Z"),
        vec![
            utc("2025-11-01T05:30:00Z"), // 01:30 EDT
            utc("2025-11-02T05:30:00Z"), // first 01:30 EDT only
            utc("2025-11-03T06:30:00Z"), // 01:30 EST
        ]
    );
}

#[test]
fn step_jobs_skip_the_gap_and_keep_their_gaps_at_the_floor() {
    let s = Schedule::parse(&text("every 30 minutes", "America/New_York")).unwrap();
    let got = occurrences(&s, "2025-03-09T06:00:00Z", "2025-03-09T08:00:00Z");
    // 01:30 EST, then 03:00 EDT (07:00Z) right after the 02:00-03:00 gap, then 03:30 EDT
    assert_eq!(
        got,
        vec![
            utc("2025-03-09T06:30:00Z"),
            utc("2025-03-09T07:00:00Z"),
            utc("2025-03-09T07:30:00Z"),
        ]
    );
    for pair in got.windows(2) {
        assert!((pair[1] - pair[0]).num_seconds() >= MIN_INTERVAL_SECS);
    }
}

#[test]
fn next_after_is_deterministic_and_strictly_increasing() {
    let a = Schedule::parse(&text("daily at 5:30 PM", "Europe/Paris")).unwrap();
    let b = Schedule::parse(&text("daily at 5:30 PM", "Europe/Paris")).unwrap();
    assert_eq!(a, b);
    let mut x = utc("2025-01-01T00:00:00Z");
    let mut y = x;
    let mut last = x;
    for _ in 0..400 {
        let nx = a.next_after(x).unwrap();
        let ny = b.next_after(y).unwrap();
        assert_eq!(nx, ny);
        assert!(nx > last);
        last = nx;
        x = nx;
        y = ny;
    }
}

#[test]
fn request_form_round_trips_through_serde() {
    for body in [
        json!({"text": "every 30 minutes", "timezone": "UTC"}),
        json!({"cron": "7-59/15 * * * *", "timezone": "Europe/Berlin"}),
        json!({"text": "daily at 5:30 PM", "timezone": "America/New_York"}),
    ] {
        let s: Schedule = serde_json::from_value(body.clone()).unwrap();
        let back = serde_json::to_value(&s).unwrap();
        assert_eq!(back, body);
        let again: Schedule = serde_json::from_value(back).unwrap();
        assert_eq!(again, s);
    }
    // an omitted zone serializes as the default
    let s: Schedule = serde_json::from_value(json!({"text": "hourly"})).unwrap();
    assert_eq!(
        serde_json::to_value(&s).unwrap(),
        json!({"text": "hourly", "timezone": "UTC"})
    );
    // validation runs on deserialize
    let e = serde_json::from_value::<Schedule>(json!({"text": "every 3 minutes"})).unwrap_err();
    assert!(e.to_string().contains("minimum interval"), "{e}");
    assert!(serde_json::from_value::<Schedule>(json!({})).is_err());
    // the stored columns rebuild an equal schedule without re-sampling
    let stored = Schedule::from_stored(s.cron(), s.timezone()).unwrap();
    assert_eq!(stored, s);
    assert!(Schedule::from_stored("nope", "UTC").is_err());
    assert!(Schedule::from_stored("0 * * * *", "Nowhere/Land").is_err());
}

#[test]
fn runs_per_30_days_estimates_the_cadence() {
    let per = |t: &str| Schedule::parse(&text(t, "UTC")).unwrap().runs_per_30_days();
    assert_eq!(per("every 30 minutes"), 1_440);
    assert_eq!(per("hourly"), 720);
    assert_eq!(per("every 15 minutes"), 2_880);
    assert_eq!(per("daily"), 30);
    assert_eq!(per("weekly"), 5);
}
