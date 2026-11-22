# Time handling

Every CrawlX crate reads and writes instants, durations and calendar dates through one facade,
`crawlx_core::time`. No crate depends on `chrono` or `chrono-tz` (RUSTSEC-2026-0543 and RUSTSEC-2026-0555 mark
both unmaintained; issue #69).

## Choice of library

| Need | Library | Why |
| --- | --- | --- |
| Instants, durations, calendar dates, database codecs | [`time`](https://crates.io/crates/time) behind the facade | sqlx 0.9 has native `time` codecs for PostgreSQL `TIMESTAMPTZ` and MySQL/MariaDB `TIMESTAMP`/`DATETIME`; it has no `jiff` codecs. The `large-dates` feature keeps the range chrono had (years -262143 to 262142), so the SQLite and MariaDB infinity sentinels (`9999-12-31`) still decode. |
| IANA zones, DST rules, cron evaluation | [`jiff`](https://crates.io/crates/jiff) with the bundled zone database | `time` has no zone database. `jiff` is maintained, and `croner` 5 evaluates five-field cron expressions on it directly (`default-features = false, features = ["std", "jiff"]`), so no chrono-typed API is left in the scheduler. The database is bundled (`tzdb-bundle-always`), so results do not depend on the host's tzdata. |

`jiff` is used only by `crawlx-scheduler` (`Schedule`) and `crawlx-extract` (`article_dates`,
`extract.content.dateTimezone`); every other crate sees only the facade types.

## The facade

| Type | Role |
| --- | --- |
| `Timestamp` | A UTC instant with nanosecond resolution. Serializes as an RFC 3339 string with `Z` and a fraction of three, six or nine digits only when the value has one. |
| `Duration` | A signed length of time. |
| `NaiveDate`, `NaiveDateTime`, `NaiveTime` | Calendar values without a zone; `NaiveDate` serializes as `YYYY-MM-DD`. |
| `FixedDateTime` | An instant with the offset its text was written in (parsed RFC 3339 and RFC 2822 values). |
| `Clock`, `SystemClock`, `ManualClock` | The injected clock of the deterministic crates. |

Wire formats are part of the contract and did not change: JSON, RFC 3339 text, `Display`, the SQLite
microsecond columns and the MariaDB `DATETIME(6)` binds. `crates/crawlx-core/tests/time_golden.rs` pins them
as literals. The readers (RFC 3339 strict and relaxed, RFC 2822, the strptime-style subset `%Y %m %d %H %M %S
%:z`) follow the former grammar, including leading white space before numbers and three-letter month names.

Database codecs for `Timestamp` and for `NaiveDateTime` (the MariaDB `DATETIME(6)` bind form) live in
`crawlx_core::time` behind the `sqlx` feature, which the crates that bind timestamps enable.

## What still depends on chrono

`chrono` remains in the dependency tree only through one third-party crate: `rskafka` (the record timestamp
is a `chrono::DateTime<Utc>`; the Kafka sink builds it with `From<SystemTime>` and never names the type).
RUSTSEC-2026-0543 therefore stays in `deny.toml`, with a comment naming the condition for removing it.
`cargo tree -i chrono` lists the edge.
