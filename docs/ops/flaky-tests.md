# Flaky tests

A flaky test fails and then passes without a code change. CrawlX treats it as a defect: the
runner reruns a failing test once, only to classify it; a pass on the rerun is reported, counted
and, after repeats, quarantined. Browser tests are not retried to make them green: a browser
flake is usually an action taken on a stale observation, and the fix is to make the test (or the
code) wait for the state it needs.

## Policy

These are planning defaults; the constants are in `crates/crawlx-bench/src/flake.rs`.

| Rule | Value | Constant |
|---|---|---|
| Automatic reruns of a failing test (classification only) | 1 | `RERUNS` |
| Flake events that quarantine a test | 3 in 14 days | `QUARANTINE_THRESHOLD`, `QUARANTINE_WINDOW_DAYS` |
| Time a quarantined test may stay quarantined | 14 days | `QUARANTINE_DEADLINE_DAYS` |
| Window of the published flake rate | 30 days | `RATE_WINDOW_DAYS` |
| Release gate: PR-suite flake rate | strictly below 1% | `RELEASE_MAX_FLAKE_PERCENT` |

A window of `n` days ending on a date covers that date and the `n - 1` days before it. An event
14 days old is outside the 14-day window; a test quarantined exactly 14 days ago is still within
its deadline, one quarantined 15 days ago is a violation.

## How it fits together

1. `.config/nextest.toml` defines the profiles `ci` and `nightly`: `retries = 1`,
   `fail-fast = false` and a junit report at `target/nextest/<profile>/junit.xml`. A test that
   failed and then passed carries a `<flakyFailure>` (or `<flakyError>`) child in the report; a
   test that failed every attempt carries `<failure>` or `<error>` and is a plain failure.
2. `flake-report record` reads one or more junit files and appends one run (`date`, `suite`,
   test executions, flaky test ids) to a JSON history. Runs older than 30 days are dropped.
3. `flake-report quarantine` adds every test with 3 flake events in the last 14 days to
   `ci/quarantine.toml`, dated today, and keeps the existing entries.
4. `flake-report filter` prints the nextest filterset for that file: without `--only` it
   excludes the quarantined tests (PR suites), with `--only` it selects only them (nightly).
5. `flake-report check` exits 1 for an entry older than 14 days.
6. `flake-report report` writes `bench/out/flake-report.json` and, with `--markdown`, an issue
   body per test with a flake event in the last 14 days.

`ci/flake-gate.sh` chains these for CI (`filter`, `record`, `gate`; see its header).

### The flake rate

`bench/out/flake-report.json` holds exactly three fields:

```json
{ "window_days": 30, "runs": 12480, "flaky_runs": 3 }
```

`runs` is the number of test executions in the window (skipped tests are not executions) and
`flaky_runs` the number of those that failed and then passed on the rerun. The flake rate is
`flaky_runs / runs`. Only PR suites count: every suite except `nightly`, whose run includes the
quarantined tests. `flake-report report --suite NAME` (repeatable) counts the named suites
instead. The release gate needs a rate strictly below 1% and at least one recorded execution;
`flake-report report --release-gate` and `ci/flake-gate.sh gate --release` exit 1 otherwise.

## Running it

```sh
# PR suite: skip the quarantined tests, rerun failures once, keep the junit report
cargo nextest run --profile ci -E "$(ci/flake-gate.sh filter)"
ci/flake-gate.sh record pr target/nextest/ci/junit.xml

# nightly: everything, then the quarantine bookkeeping
cargo nextest run --profile nightly
ci/flake-gate.sh record nightly target/nextest/nightly/junit.xml
ci/flake-gate.sh gate
```

The history file (`bench/out/flake-history.json`, `FLAKE_HISTORY` overrides it) has to persist
between runs; CI restores and saves it with a rolling cache key. `--date` (`FLAKE_DATE` for the
script) defaults to today in UTC; the library never reads the clock.

Test ids are `<binary id>::<test name>`, for example
`crawlx-bench::lane_chromium::link_fixtures_run_entirely_on_the_trusted_lane`. The binary id is
the crate for library tests and `crate::target` for integration tests, and a test name may
contain `::` too, so an id with more than one `::` is read both ways in the filterset (it can
only exclude more than intended in the unlikely case that both readings exist).

## When a test is flaky

1. Read the issue body from `bench/out/flake-issues.md` and file one issue per test; it lists the
   flake events and the deadline.
2. Find the cause. Reproduce with `cargo nextest run --profile ci -E 'test(=NAME)' --stress-count 20`
   (or a shell loop), read the failing assertion, and fix the cause: wait for the observable
   state the test needs instead of sleeping, and never loosen an assertion or add a retry.
3. A test quarantined by `flake-report quarantine` runs only in the nightly suite. Fix it or
   delete it within 14 days; remove its entry from `ci/quarantine.toml` in the same change. After
   14 days `flake-report check` fails the nightly run until the entry is gone.
