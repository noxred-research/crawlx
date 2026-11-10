//! Flake handling: classify reruns, keep a flake history, quarantine repeat offenders and publish
//! the flake rate the release gate reads.
//!
//! Policy (planning defaults, named constants below):
//!
//! * A failing test is rerun once, only to classify it. A test that fails and passes on the rerun
//!   is `flaky` and is reported, so an issue can be filed ([`issue_body`]). The rerun is the
//!   runner's (`retries = 1` in `.config/nextest.toml`); this module reads its junit output
//!   ([`JunitReport::parse`]).
//! * A test with [`QUARANTINE_THRESHOLD`] or more flake events in a [`QUARANTINE_WINDOW_DAYS`]-day
//!   window is quarantined: it is excluded from the PR suites ([`Quarantine::filterset_exclude`])
//!   and runs only in the nightly suite ([`Quarantine::filterset_only`]). A quarantine older than
//!   [`QUARANTINE_DEADLINE_DAYS`] is a violation ([`Quarantine::expired`]): the test is fixed or
//!   deleted by then.
//! * The suite publishes a flake rate, flaky test executions over all test executions in a
//!   [`RATE_WINDOW_DAYS`]-day window ([`History::summary`], written as [`FlakeSummary`]); the
//!   release gate needs it below [`RELEASE_MAX_FLAKE_PERCENT`] percent
//!   ([`FlakeSummary::meets_release_gate`]).
//!
//! Dates are explicit inputs: nothing here reads the wall clock. A window of `n` days ending at
//! `today` covers the `n` calendar dates `today - (n - 1)` through `today` inclusive, so an event
//! on `today - n` is outside it. Every ordered output is sorted (`BTreeMap`/`BTreeSet`), so the
//! same inputs give byte-identical files.
//!
//! The junit reader is a small tag scanner, not a general XML parser: it understands start, end
//! and empty tags, quoted attributes with the five predefined and numeric entities, comments,
//! processing instructions, declarations and CDATA (whose content is skipped, so captured test
//! output cannot forge a result).

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Automatic reruns of a failing test. The rerun only classifies the failure.
pub const RERUNS: u32 = 1;
/// Flake events inside [`QUARANTINE_WINDOW_DAYS`] that quarantine a test.
pub const QUARANTINE_THRESHOLD: usize = 3;
/// Window, in days, over which flake events are counted for quarantine.
pub const QUARANTINE_WINDOW_DAYS: u32 = 14;
/// Days a test may stay quarantined before it must be fixed or deleted.
pub const QUARANTINE_DEADLINE_DAYS: u32 = 14;
/// Window, in days, of the published flake rate (and the horizon the history is pruned to).
pub const RATE_WINDOW_DAYS: u32 = 30;
/// The release gate needs the PR-suite flake rate strictly below this many percent.
pub const RELEASE_MAX_FLAKE_PERCENT: u64 = 1;
/// The suite name of the nightly run: it executes the quarantined tests, so it is not a PR suite
/// and its flakes do not count against the release gate.
pub const NIGHTLY_SUITE: &str = "nightly";
/// Schema version of the history file.
pub const HISTORY_VERSION: u32 = 1;

/// Header written at the top of the quarantine file.
pub const QUARANTINE_HEADER: &str = "\
# Quarantined flaky tests: excluded from the PR suites, run only by the nightly suite.
# A test enters here after 3 flake events in 14 days (`flake-report quarantine`) and must be
# fixed or deleted within 14 days of `since`; `flake-report check` fails on an older entry.
# Entries are `[[test]]` tables with `id = \"<binary id>::<test name>\"`, `since = \"YYYY-MM-DD\"`
# and `reason`. Remove an entry in the change that fixes or deletes the test.
";

/// Everything that can fail in flake handling.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FlakeError {
    /// The junit document is not well formed enough to read.
    #[error("junit xml at byte {offset}: {reason}")]
    Junit {
        /// Byte offset in the document.
        offset: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// The history file has a version this build does not read.
    #[error("history version {found} is not supported (expected {expected})")]
    HistoryVersion {
        /// The version in the file.
        found: u32,
        /// The version this build reads.
        expected: u32,
    },
    /// The history file is not valid JSON of the expected shape.
    #[error("history json")]
    Json(#[from] serde_json::Error),
    /// The quarantine file is not valid TOML of the expected shape.
    #[error("quarantine file")]
    QuarantineParse(#[from] toml::de::Error),
    /// The quarantine file could not be encoded.
    #[error("quarantine file encode")]
    QuarantineEncode(#[from] toml::ser::Error),
    /// A test id is not `binary::test`.
    #[error("test id `{0}` is not `<binary id>::<test name>`")]
    InvalidTestId(String),
    /// The quarantine file lists a test twice.
    #[error("test id `{0}` is quarantined twice")]
    DuplicateQuarantine(String),
    /// File system access.
    #[error("i/o on {path}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl FlakeError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// What one test did in one run. The declaration order is the severity order used when the same
/// test is reported twice: the worse outcome wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Outcome {
    /// Not executed.
    Skipped,
    /// Passed on the first attempt.
    Pass,
    /// Failed, then passed on the rerun.
    Flaky,
    /// Failed every attempt.
    Failed,
}

/// Per-test outcomes of one or more junit documents, keyed by `binary::test`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JunitReport {
    cases: BTreeMap<String, Outcome>,
}

impl JunitReport {
    /// Reads the test cases of a junit document as written by `cargo nextest` (`<testsuite>`
    /// named by binary id, `<testcase name classname>` with `<failure>`/`<error>` for a final
    /// failure, `<flakyFailure>`/`<flakyError>` for failed attempts of a test that then passed,
    /// `<skipped>` for a skipped test).
    ///
    /// # Errors
    /// [`FlakeError::Junit`] when a tag is unterminated or mismatched or a `<testcase>` has no
    /// `name`.
    pub fn parse(xml: &str) -> Result<Self, FlakeError> {
        let mut cases = BTreeMap::new();
        let mut stack: Vec<&str> = Vec::new();
        let mut suite = String::new();
        let mut case: Option<Case> = None;
        let mut pos = 0usize;
        while let Some(tag) = next_tag(xml, &mut pos)? {
            match tag.kind {
                TagKind::End => {
                    let Some(open) = stack.pop() else {
                        return Err(junit_err(tag.offset, "end tag without a start tag"));
                    };
                    if open != tag.name {
                        return Err(junit_err(tag.offset, "mismatched end tag"));
                    }
                    if open == "testcase" && case.as_ref().is_some_and(|c| c.depth == stack.len()) {
                        if let Some(done) = case.take() {
                            insert_case(&mut cases, done);
                        }
                    }
                }
                TagKind::Start | TagKind::Empty => {
                    let empty = tag.kind == TagKind::Empty;
                    match tag.name {
                        "testsuite" => {
                            suite = attribute(tag.attrs, "name").unwrap_or_default();
                        }
                        "testcase" => {
                            let name = attribute(tag.attrs, "name")
                                .ok_or_else(|| junit_err(tag.offset, "testcase without a name"))?;
                            let binary = attribute(tag.attrs, "classname").unwrap_or_else(|| suite.clone());
                            let fresh = Case {
                                id: format!("{binary}::{name}"),
                                depth: stack.len(),
                                outcome: None,
                            };
                            if empty {
                                insert_case(&mut cases, fresh);
                            } else {
                                case = Some(fresh);
                            }
                        }
                        child => {
                            if let Some(open) = case.as_mut() {
                                // a direct child of the open testcase
                                if stack.len() == open.depth + 1 {
                                    let seen = match child {
                                        "failure" | "error" => Some(Outcome::Failed),
                                        "skipped" => Some(Outcome::Skipped),
                                        "flakyFailure" | "flakyError" => Some(Outcome::Flaky),
                                        _ => None,
                                    };
                                    if let Some(seen) = seen {
                                        open.outcome = open.outcome.max(Some(seen));
                                    }
                                }
                            }
                        }
                    }
                    if !empty {
                        stack.push(tag.name);
                    }
                }
            }
        }
        if !stack.is_empty() {
            return Err(junit_err(xml.len(), "unclosed element"));
        }
        Ok(Self { cases })
    }

    /// Adds the cases of `other`; a test present in both keeps the worse outcome.
    pub fn merge(&mut self, other: Self) {
        for (id, outcome) in other.cases {
            let slot = self.cases.entry(id).or_insert(outcome);
            *slot = (*slot).max(outcome);
        }
    }

    /// Every test and its outcome, ordered by id.
    #[must_use]
    pub fn cases(&self) -> &BTreeMap<String, Outcome> {
        &self.cases
    }

    /// Tests that were executed (everything but [`Outcome::Skipped`]).
    #[must_use]
    pub fn executions(&self) -> u64 {
        to_u64(self.cases.values().filter(|o| **o != Outcome::Skipped).count())
    }

    /// The ids of the tests with the given outcome, ordered.
    #[must_use]
    pub fn with_outcome(&self, outcome: Outcome) -> Vec<&str> {
        self.cases
            .iter()
            .filter(|(_, o)| **o == outcome)
            .map(|(id, _)| id.as_str())
            .collect()
    }
}

struct Case {
    id: String,
    depth: usize,
    /// The worst child seen so far; `None` is a pass.
    outcome: Option<Outcome>,
}

fn insert_case(cases: &mut BTreeMap<String, Outcome>, case: Case) {
    let outcome = case.outcome.unwrap_or(Outcome::Pass);
    let slot = cases.entry(case.id).or_insert(outcome);
    *slot = (*slot).max(outcome);
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn junit_err(offset: usize, reason: &'static str) -> FlakeError {
    FlakeError::Junit { offset, reason }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TagKind {
    Start,
    End,
    Empty,
}

struct Tag<'a> {
    kind: TagKind,
    name: &'a str,
    attrs: &'a str,
    offset: usize,
}

/// The next element tag at or after `*pos`; comments, processing instructions, declarations and
/// CDATA are skipped whole.
fn next_tag<'a>(xml: &'a str, pos: &mut usize) -> Result<Option<Tag<'a>>, FlakeError> {
    loop {
        let Some(rel) = xml[*pos..].find('<') else {
            *pos = xml.len();
            return Ok(None);
        };
        let start = *pos + rel;
        let rest = &xml[start..];
        let skip = |open: &str, close: &str| -> Result<usize, FlakeError> {
            rest[open.len()..]
                .find(close)
                .map(|i| start + open.len() + i + close.len())
                .ok_or_else(|| junit_err(start, "unterminated markup"))
        };
        if rest.starts_with("<!--") {
            *pos = skip("<!--", "-->")?;
        } else if rest.starts_with("<![CDATA[") {
            *pos = skip("<![CDATA[", "]]>")?;
        } else if rest.starts_with("<?") {
            *pos = skip("<?", "?>")?;
        } else if rest.starts_with("<!") {
            *pos = skip("<!", ">")?;
        } else {
            let end = tag_end(rest).ok_or_else(|| junit_err(start, "unterminated tag"))?;
            *pos = start + end + 1;
            let inner = &rest[1..end];
            let tag = if let Some(name) = inner.strip_prefix('/') {
                Tag {
                    kind: TagKind::End,
                    name: name.trim(),
                    attrs: "",
                    offset: start,
                }
            } else {
                let (inner, kind) = match inner.strip_suffix('/') {
                    Some(inner) => (inner, TagKind::Empty),
                    None => (inner, TagKind::Start),
                };
                let name_end = inner
                    .find(|c: char| c.is_ascii_whitespace())
                    .unwrap_or(inner.len());
                Tag {
                    kind,
                    name: &inner[..name_end],
                    attrs: &inner[name_end..],
                    offset: start,
                }
            };
            if tag.name.is_empty() {
                return Err(junit_err(start, "tag without a name"));
            }
            return Ok(Some(tag));
        }
    }
}

/// Index of the `>` closing the tag that opens `rest`, skipping quoted attribute values.
fn tag_end(rest: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in rest.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(i),
            (None, _) => {}
        }
    }
    None
}

/// The decoded value of attribute `key` in the attribute text of a tag.
fn attribute(attrs: &str, key: &str) -> Option<String> {
    let mut rest = attrs.trim_start();
    while !rest.is_empty() {
        let name_end = rest
            .find(|c: char| c == '=' || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        let after = rest[name_end..].trim_start().strip_prefix('=')?.trim_start();
        let quote = after.chars().next().filter(|c| matches!(c, '"' | '\''))?;
        let body = &after[1..];
        let close = body.find(quote)?;
        if name == key {
            return Some(unescape(&body[..close]));
        }
        rest = body[close + 1..].trim_start();
    }
    None
}

/// Decodes the predefined and numeric character references; an unknown reference stays as written.
fn unescape(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.find(';').and_then(|semi| {
            let entity = &rest[1..semi];
            let ch = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => entity
                    .strip_prefix("#x")
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            };
            ch.map(|c| (c, semi + 1))
        });
        match decoded {
            Some((c, used)) => {
                out.push(c);
                rest = &rest[used..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// One recorded test run: how many tests executed and which of them were flaky.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    /// The day of the run.
    pub date: NaiveDate,
    /// The suite name (`ci`, `browser`, [`NIGHTLY_SUITE`], ...).
    pub suite: String,
    /// Test executions in the run (skipped tests excluded).
    pub executions: u64,
    /// Ids of the tests that failed and then passed on the rerun, ordered.
    pub flaky: Vec<String>,
}

/// The versioned flake history: the runs of the last [`RATE_WINDOW_DAYS`] days.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct History {
    /// Schema version ([`HISTORY_VERSION`]).
    pub version: u32,
    /// The recorded runs, ordered by `(date, suite)`.
    pub runs: Vec<Run>,
}

impl Default for History {
    fn default() -> Self {
        Self {
            version: HISTORY_VERSION,
            runs: Vec::new(),
        }
    }
}

/// Whether `date` lies in the `days`-day window ending at `today` (see the module docs).
#[must_use]
pub fn in_window(date: NaiveDate, today: NaiveDate, days: u32) -> bool {
    let age = today.signed_duration_since(date).num_days();
    age >= 0 && age < i64::from(days)
}

impl History {
    /// Decodes a history document.
    ///
    /// # Errors
    /// [`FlakeError::Json`] for malformed JSON, [`FlakeError::HistoryVersion`] for another version.
    pub fn from_json(text: &str) -> Result<Self, FlakeError> {
        let history: Self = serde_json::from_str(text)?;
        if history.version != HISTORY_VERSION {
            return Err(FlakeError::HistoryVersion {
                found: history.version,
                expected: HISTORY_VERSION,
            });
        }
        Ok(history)
    }

    /// The history document, pretty-printed with a trailing newline.
    ///
    /// # Errors
    /// [`FlakeError::Json`] if serialization fails.
    pub fn to_json(&self) -> Result<String, FlakeError> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Reads the history at `path`; a missing file is an empty history.
    ///
    /// # Errors
    /// [`FlakeError::Io`] on a read error other than not-found, plus the decode errors.
    pub fn load(path: &Path) -> Result<Self, FlakeError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(FlakeError::io(path, e)),
        }
    }

    /// Writes the history to `path`, creating parent directories.
    ///
    /// # Errors
    /// [`FlakeError::Io`] on a write error.
    pub fn save(&self, path: &Path) -> Result<(), FlakeError> {
        write_file(path, &self.to_json()?)
    }

    /// Appends one run of `suite` on `date` from `report`, then drops runs older than the rate
    /// window ending at `date`. Runs stay ordered by `(date, suite)`; two runs of the same suite
    /// on one day are both kept (each is a separate set of executions).
    pub fn record(&mut self, date: NaiveDate, suite: &str, report: &JunitReport) {
        self.runs.push(Run {
            date,
            suite: suite.to_owned(),
            executions: report.executions(),
            flaky: report
                .with_outcome(Outcome::Flaky)
                .into_iter()
                .map(str::to_owned)
                .collect(),
        });
        self.runs
            .retain(|r| in_window(r.date, date, RATE_WINDOW_DAYS) || r.date > date);
        self.runs
            .sort_by(|a, b| (a.date, &a.suite).cmp(&(b.date, &b.suite)));
    }

    /// Flake events per test inside the quarantine window ending at `today`, over every suite.
    /// A test contributes one event, dated by the run, per run in which it was flaky.
    #[must_use]
    pub fn flake_events(&self, today: NaiveDate) -> BTreeMap<String, Vec<NaiveDate>> {
        let mut events: BTreeMap<String, Vec<NaiveDate>> = BTreeMap::new();
        for run in &self.runs {
            if !in_window(run.date, today, QUARANTINE_WINDOW_DAYS) {
                continue;
            }
            let unique: BTreeSet<&String> = run.flaky.iter().collect();
            for id in unique {
                events.entry(id.clone()).or_default().push(run.date);
            }
        }
        for dates in events.values_mut() {
            dates.sort_unstable();
        }
        events
    }

    /// Tests with at least [`QUARANTINE_THRESHOLD`] flake events in the window ending at `today`,
    /// with their events.
    #[must_use]
    pub fn quarantine_candidates(&self, today: NaiveDate) -> BTreeMap<String, Vec<NaiveDate>> {
        let mut events = self.flake_events(today);
        events.retain(|_, dates| dates.len() >= QUARANTINE_THRESHOLD);
        events
    }

    /// The flake rate over the [`RATE_WINDOW_DAYS`] window ending at `today`, counting the runs of
    /// the suites for which `include` is true.
    #[must_use]
    pub fn summary(&self, today: NaiveDate, include: impl Fn(&str) -> bool) -> FlakeSummary {
        let mut runs = 0u64;
        let mut flaky_runs = 0u64;
        for run in &self.runs {
            if in_window(run.date, today, RATE_WINDOW_DAYS) && include(&run.suite) {
                runs = runs.saturating_add(run.executions);
                let unique: BTreeSet<&String> = run.flaky.iter().collect();
                flaky_runs = flaky_runs.saturating_add(to_u64(unique.len()));
            }
        }
        FlakeSummary {
            window_days: RATE_WINDOW_DAYS,
            runs,
            flaky_runs,
        }
    }

    /// [`History::summary`] over the PR suites: every suite except [`NIGHTLY_SUITE`].
    #[must_use]
    pub fn pr_summary(&self, today: NaiveDate) -> FlakeSummary {
        self.summary(today, |suite| suite != NIGHTLY_SUITE)
    }
}

/// The published flake rate: `bench/out/flake-report.json` holds exactly these three fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeSummary {
    /// Length of the window in days.
    pub window_days: u32,
    /// Test executions in the window.
    pub runs: u64,
    /// Flaky test executions in the window.
    pub flaky_runs: u64,
}

impl FlakeSummary {
    /// Flaky executions over all executions, as a fraction; `None` without executions.
    #[must_use]
    pub fn rate(&self) -> Option<f64> {
        if self.runs == 0 {
            return None;
        }
        // counts stay far below 2^53, so the division is exact enough for display
        #[allow(clippy::cast_precision_loss)]
        let rate = self.flaky_runs as f64 / self.runs as f64;
        Some(rate)
    }

    /// Whether the rate is strictly below [`RELEASE_MAX_FLAKE_PERCENT`] percent. Without
    /// executions there is no evidence, so the gate does not pass.
    #[must_use]
    pub fn meets_release_gate(&self) -> bool {
        self.runs > 0
            && u128::from(self.flaky_runs) * 100
                < u128::from(self.runs) * u128::from(RELEASE_MAX_FLAKE_PERCENT)
    }

    /// The summary document, pretty-printed with a trailing newline.
    ///
    /// # Errors
    /// [`FlakeError::Json`] if serialization fails.
    pub fn to_json(&self) -> Result<String, FlakeError> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Writes the summary to `path`, creating parent directories.
    ///
    /// # Errors
    /// [`FlakeError::Io`] on a write error.
    pub fn save(&self, path: &Path) -> Result<(), FlakeError> {
        write_file(path, &self.to_json()?)
    }
}

/// One quarantined test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// `<binary id>::<test name>`.
    pub id: String,
    /// The day the test was quarantined.
    pub since: NaiveDate,
    /// Why (the flake events that triggered it, or an operator's note).
    pub reason: String,
}

/// The quarantine file (`ci/quarantine.toml`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quarantine {
    /// The quarantined tests, ordered by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test: Vec<QuarantineEntry>,
}

impl Quarantine {
    /// Decodes a quarantine file; entries are validated and ordered by id.
    ///
    /// # Errors
    /// [`FlakeError::QuarantineParse`], [`FlakeError::InvalidTestId`],
    /// [`FlakeError::DuplicateQuarantine`].
    pub fn from_toml(text: &str) -> Result<Self, FlakeError> {
        let mut file: Self = toml::from_str(text)?;
        file.test.sort_by(|a, b| a.id.cmp(&b.id));
        for entry in &file.test {
            split_candidates(&entry.id)?;
        }
        if let Some(pair) = file.test.windows(2).find(|w| w[0].id == w[1].id) {
            return Err(FlakeError::DuplicateQuarantine(pair[0].id.clone()));
        }
        Ok(file)
    }

    /// The quarantine file text: [`QUARANTINE_HEADER`] then the entries ordered by id.
    ///
    /// # Errors
    /// [`FlakeError::QuarantineEncode`] if encoding fails.
    pub fn to_toml(&self) -> Result<String, FlakeError> {
        let mut sorted = self.clone();
        sorted.test.sort_by(|a, b| a.id.cmp(&b.id));
        let mut text = String::from(QUARANTINE_HEADER);
        if !sorted.test.is_empty() {
            text.push('\n');
            text.push_str(&toml::to_string(&sorted)?);
        }
        Ok(text)
    }

    /// Reads the file at `path`; a missing file is an empty quarantine.
    ///
    /// # Errors
    /// [`FlakeError::Io`] on a read error other than not-found, plus the decode errors.
    pub fn load(path: &Path) -> Result<Self, FlakeError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(FlakeError::io(path, e)),
        }
    }

    /// Writes the file to `path`, creating parent directories.
    ///
    /// # Errors
    /// [`FlakeError::Io`] on a write error, [`FlakeError::QuarantineEncode`].
    pub fn save(&self, path: &Path) -> Result<(), FlakeError> {
        write_file(path, &self.to_toml()?)
    }

    /// Adds every candidate not yet quarantined, dated `today`; existing entries are kept as
    /// they are. Returns the ids added, ordered.
    pub fn add_candidates(
        &mut self,
        candidates: &BTreeMap<String, Vec<NaiveDate>>,
        today: NaiveDate,
    ) -> Vec<String> {
        let mut added = Vec::new();
        for (id, events) in candidates {
            if self.test.iter().any(|e| &e.id == id) {
                continue;
            }
            self.test.push(QuarantineEntry {
                id: id.clone(),
                since: today,
                reason: format!(
                    "{} flake events in {} days (latest {})",
                    events.len(),
                    QUARANTINE_WINDOW_DAYS,
                    events
                        .last()
                        .map_or_else(|| today.to_string(), ToString::to_string)
                ),
            });
            added.push(id.clone());
        }
        self.test.sort_by(|a, b| a.id.cmp(&b.id));
        added
    }

    /// Entries quarantined for more than [`QUARANTINE_DEADLINE_DAYS`] days at `today`: they must
    /// be fixed or deleted. An entry dated `today - 14` is still within the deadline.
    #[must_use]
    pub fn expired(&self, today: NaiveDate) -> Vec<&QuarantineEntry> {
        self.test
            .iter()
            .filter(|e| today.signed_duration_since(e.since).num_days() > i64::from(QUARANTINE_DEADLINE_DAYS))
            .collect()
    }

    /// A nextest filterset matching every test except the quarantined ones (`all()` when none):
    /// the PR profile's `-E` argument.
    #[must_use]
    pub fn filterset_exclude(&self) -> String {
        match self.matcher() {
            Some(matcher) => format!("not ({matcher})"),
            None => "all()".to_owned(),
        }
    }

    /// A nextest filterset matching only the quarantined tests (`none()` when there are none):
    /// the `nightly --quarantined` run's `-E` argument.
    #[must_use]
    pub fn filterset_only(&self) -> String {
        self.matcher().unwrap_or_else(|| "none()".to_owned())
    }

    fn matcher(&self) -> Option<String> {
        let mut ids: Vec<&str> = self.test.iter().map(|e| e.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        let parts: Vec<String> = ids.into_iter().filter_map(id_expr).collect();
        (!parts.is_empty()).then(|| parts.join(" | "))
    }
}

/// The `(binary id, test name)` readings of `binary::test`. A binary id is the crate name
/// (library tests) or `crate::target` (integration tests, `bin/name`), and a test name may itself
/// contain `::` (module path), so ids with several `::` have two readings.
fn split_candidates(id: &str) -> Result<Vec<(String, String)>, FlakeError> {
    let segments: Vec<&str> = id.split("::").collect();
    let readings: Vec<(String, String)> = (1..=2)
        .filter(|binary_len| segments.len() > *binary_len)
        .map(|binary_len| {
            (
                segments[..binary_len].join("::"),
                segments[binary_len..].join("::"),
            )
        })
        .filter(|(binary, test)| {
            !binary.is_empty() && !test.is_empty() && !binary.contains(char::is_whitespace)
        })
        .collect();
    if readings.is_empty() {
        return Err(FlakeError::InvalidTestId(id.to_owned()));
    }
    Ok(readings)
}

fn id_expr(id: &str) -> Option<String> {
    let readings = split_candidates(id).ok()?;
    let exprs: Vec<String> = readings
        .iter()
        .map(|(binary, test)| {
            format!(
                "(binary_id(={}) & test(={}))",
                escape_filter(binary),
                escape_filter(test)
            )
        })
        .collect();
    Some(if exprs.len() == 1 {
        exprs.into_iter().collect()
    } else {
        format!("({})", exprs.join(" | "))
    })
}

/// Escapes the characters that end a filterset matcher argument.
fn escape_filter(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | ')' | ',') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Title of the issue to file for a flaky test.
#[must_use]
pub fn issue_title(id: &str) -> String {
    format!("Flaky test: {id}")
}

/// Markdown body of the issue to file for flaky test `id`: its flake events in the quarantine
/// window ending at `today`, the quarantine state and the policy that applies.
#[must_use]
pub fn issue_body(id: &str, events: &[NaiveDate], quarantine: &Quarantine, today: NaiveDate) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "`{id}` failed and then passed on the automatic rerun.");
    out.push('\n');
    let _ = writeln!(
        out,
        "Flake events in the {QUARANTINE_WINDOW_DAYS} days ending {today}: {}",
        events.len()
    );
    for date in events {
        let _ = writeln!(out, "- {date}");
    }
    out.push('\n');
    match quarantine.test.iter().find(|e| e.id == id) {
        Some(entry) => {
            let deadline = entry
                .since
                .checked_add_days(chrono::Days::new(u64::from(QUARANTINE_DEADLINE_DAYS)));
            let _ = writeln!(
                out,
                "Quarantined since {} ({}); it runs only in the nightly suite. Fix or delete it by {}.",
                entry.since,
                entry.reason,
                deadline.map_or_else(|| "the deadline".to_owned(), |d| d.to_string())
            );
        }
        None if events.len() >= QUARANTINE_THRESHOLD => {
            let _ = writeln!(
                out,
                "Quarantine threshold ({QUARANTINE_THRESHOLD} events in {QUARANTINE_WINDOW_DAYS} days) reached: run `flake-report quarantine`."
            );
        }
        None => {
            let _ = writeln!(
                out,
                "Not quarantined: {QUARANTINE_THRESHOLD} events in {QUARANTINE_WINDOW_DAYS} days quarantine a test."
            );
        }
    }
    let _ = writeln!(
        out,
        "A quarantined test must be fixed or deleted within {QUARANTINE_DEADLINE_DAYS} days. Browser flakes are usually an action taken on a stale observation: fix the cause, do not add a retry."
    );
    out
}

/// Markdown report for `today`: the flake rate and one issue section per test with a flake event
/// in the quarantine window, ordered by id.
#[must_use]
pub fn report_markdown(history: &History, quarantine: &Quarantine, today: NaiveDate) -> String {
    let summary = history.pr_summary(today);
    let mut out = String::from("# Flaky tests\n\n");
    let rate = summary.rate().map_or_else(
        || "n/a (no executions)".to_owned(),
        |r| format!("{:.3}%", r * 100.0),
    );
    let _ = writeln!(
        out,
        "PR-suite flake rate over {} days: {} flaky of {} executions ({rate}); release gate needs < {RELEASE_MAX_FLAKE_PERCENT}%.\n",
        summary.window_days, summary.flaky_runs, summary.runs
    );
    let events = history.flake_events(today);
    if events.is_empty() {
        let _ = writeln!(out, "No flake events in the last {QUARANTINE_WINDOW_DAYS} days.");
    }
    for (id, dates) in &events {
        let _ = writeln!(out, "## {}\n", issue_title(id));
        out.push_str(&issue_body(id, dates, quarantine, today));
        out.push('\n');
    }
    out
}

fn write_file(path: &Path, text: &str) -> Result<(), FlakeError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| FlakeError::io(parent, e))?;
    }
    std::fs::write(path, text).map_err(|e| FlakeError::io(path, e))
}
