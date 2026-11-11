//! `release-gate`: the release checklist computed from machine-readable evidence.
//!
//! [`evaluate`] reads an evidence directory (default `bench/out`, see `docs/ops/release-gates.md`
//! for the layout) plus a few repository files and returns a [`ReleaseReport`]: one
//! [`ItemReport`] per checklist item with the state `pass`, `fail`, `unmeasured`, `waived` or
//! `not_applicable`. A release is ready only when every applicable item passes or carries a
//! valid waiver. Nothing is defaulted to a pass: an item whose evidence file is absent is
//! `unmeasured`, and `unmeasured` blocks the release exactly like `fail`.
//!
//! Evidence comes from three kinds of producers:
//!
//! * structured reports that the other bench binaries already write (`g1-report.json`,
//!   `soak-report.json`, scorecards, the cargo-mutants `outcomes.json`);
//! * suite results recorded by `release-gate record`, which runs a command and stores its exit
//!   status and libtest summary ([`SuiteEvidence`]); the verdict is recomputed from those
//!   numbers, never read from a caller-supplied boolean;
//! * repository files read at evaluation time (the Chromium pin, the alert rules, the runbooks
//!   and the telemetry metric catalog).
//!
//! A waiver ([`Waiver`]) can turn a failing or unmeasured *performance* row into `waived`. It
//! needs an owner, a reason and an expiry date, and it stops applying after that date. Waivers
//! for items that are not waivable, for unknown items or with missing fields are rejected
//! outright rather than ignored.
//!
//! The evaluation takes the date as an argument and reads no clock.

use crate::error::BenchError;
use crate::gates::{ChaosEvidence, G1Report};
use crate::gym::fixtures::catalog_row;
use crate::scorecard::Scorecard;
use crate::stats::{Direction, PairedComparison};
use chrono::NaiveDate;
use crawlx_core::config::SafetyProfile;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// `cargo-mutants` score floor on `crawlx-safety`, in percent of viable mutants caught.
pub const MUTANTS_MIN_PERCENT: u64 = 95;
/// Largest state false-split rate on G26.
pub const STATE_FALSE_SPLIT_MAX: f64 = 0.05;
/// Largest identity collision rate on G02/G06 (0.5 %).
pub const IDENTITY_COLLISION_MAX: f64 = 0.005;
/// Largest identity split rate on G02/G06 (2 %).
pub const IDENTITY_SPLIT_MAX: f64 = 0.02;
/// Smallest interactive-target recall over the AX-addressable targets.
pub const TARGET_RECALL_MIN: f64 = 0.95;
/// Smallest interactive-target precision over the AX-addressable targets.
pub const TARGET_PRECISION_MIN: f64 = 0.95;
/// Smallest enablement replay success on G11.
pub const ENABLEMENT_REPLAY_MIN: f64 = 0.9;
/// Largest false enablement edge rate on G09/G10.
pub const FALSE_ENABLEMENT_EDGE_MAX: f64 = 0.10;
/// Largest quiescence timeout rate on non-adversarial fixtures.
pub const QUIESCENCE_TIMEOUT_MAX: f64 = 0.02;
/// Catalog rows whose quiescence is adversarial by construction (infinite feed, live clocks,
/// prompt injection) and which the quiescence rate excludes.
pub const QUIESCENCE_EXEMPT_ROWS: [&str; 3] = ["G07", "G08", "G21"];
/// Smallest trusted-lane share of the actions of every scorecard.
pub const TRUSTED_LANE_SHARE_MIN: f64 = 0.99;
/// Largest drop of the different-seed Jaccard against the previous release.
pub const DIFFERENT_SEED_JACCARD_MAX_DROP: f64 = 0.03;
/// Tolerance for the float comparison of two measured Jaccard means.
const JACCARD_EPSILON: f64 = 1e-9;
/// Shortest flake-report window.
pub const FLAKE_WINDOW_DAYS: u32 = 30;
/// The flake rate must stay strictly below this many percent.
pub const FLAKE_RATE_LIMIT_PERCENT: u64 = 1;
/// Shortest soak that counts as the release soak (24 h).
pub const SOAK_MIN_SECONDS: f64 = 24.0 * 3600.0;
/// Oldest accepted restore drill.
pub const RESTORE_DRILL_MAX_AGE_DAYS: i64 = 90;

/// Suite results the checklist reads from `suites/<id>.json`; `release-gate record --id` accepts
/// exactly these ids.
pub const SUITE_IDS: [&str; 12] = [
    "ssrf_matrix",
    "scope_escape",
    "secret_canary_zdr",
    "cargo_deny",
    "stale_proposal_executions",
    "differential_extraction",
    "snapshots_unchanged",
    "criterion_gates",
    "chaos_slo",
    "model_breaker_outage",
    "migrations_tested",
    "chromium_upgrade",
];

/// Checklist category.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Category {
    /// Safety and security (hard blockers).
    SafetySecurity,
    /// Correctness.
    Correctness,
    /// Compatibility.
    Compatibility,
    /// Performance and reliability.
    PerformanceReliability,
    /// Model (only when the model tier changes).
    Model,
    /// Operations.
    Operations,
}

impl Category {
    const ALL: [Self; 6] = [
        Self::SafetySecurity,
        Self::Correctness,
        Self::Compatibility,
        Self::PerformanceReliability,
        Self::Model,
        Self::Operations,
    ];

    /// Heading of the category in the markdown checklist.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SafetySecurity => "Safety and security (hard blockers)",
            Self::Correctness => "Correctness",
            Self::Compatibility => "Compatibility",
            Self::PerformanceReliability => "Performance and reliability",
            Self::Model => "Model (only when the model tier changes)",
            Self::Operations => "Operations",
        }
    }
}

/// State of one checklist item.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ItemState {
    /// Evidence present and within the threshold.
    Pass,
    /// Evidence present and outside the threshold, or unreadable.
    Fail,
    /// No (or not enough) evidence. Blocks the release.
    Unmeasured,
    /// A failing or unmeasured performance row covered by an unexpired waiver.
    Waived,
    /// The item does not apply to this release.
    NotApplicable,
}

impl ItemState {
    /// Lowercase name, as in the JSON report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Unmeasured => "unmeasured",
            Self::Waived => "waived",
            Self::NotApplicable => "not_applicable",
        }
    }

    const fn clears(self) -> bool {
        matches!(self, Self::Pass | Self::Waived | Self::NotApplicable)
    }
}

/// A recorded waiver of one performance row.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// Checklist item id (a waivable one).
    pub item: String,
    /// Person or team accountable for the waiver.
    pub owner: String,
    /// Why the row may miss its target for this release.
    pub reason: String,
    /// Last day (`YYYY-MM-DD`, inclusive) the waiver applies.
    pub expires: String,
}

/// Contents of a waivers file: `{"waivers": [ ... ]}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaiverFile {
    waivers: Vec<Waiver>,
}

/// Parse a waivers file.
///
/// # Errors
/// [`BenchError::Json`] when the text is not a waivers document.
pub fn parse_waivers(text: &str) -> Result<Vec<Waiver>, BenchError> {
    Ok(serde_json::from_str::<WaiverFile>(text)?.waivers)
}

/// One checklist line of the report.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ItemReport {
    /// Stable item id.
    pub id: String,
    /// Category.
    pub category: Category,
    /// What the item requires.
    pub title: String,
    /// State.
    pub state: ItemState,
    /// Measured values, or why the item failed or is unmeasured.
    pub detail: String,
    /// Evidence files (relative to the evidence directory or the repository) the item reads.
    pub evidence: Vec<String>,
    /// The waiver that produced `waived`.
    pub waiver: Option<Waiver>,
}

/// Item counts per state.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Counts {
    /// `pass` items.
    pub pass: u64,
    /// `fail` items.
    pub fail: u64,
    /// `unmeasured` items.
    pub unmeasured: u64,
    /// `waived` items.
    pub waived: u64,
    /// `not_applicable` items.
    pub not_applicable: u64,
}

/// The computed checklist (`release-checklist.json`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReleaseReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Date the waivers and the restore drill were judged against (`YYYY-MM-DD`).
    pub evaluated_on: String,
    /// `true` when every applicable item passes or is waived.
    pub release_ready: bool,
    /// Item counts.
    pub counts: Counts,
    /// Items in checklist order.
    pub items: Vec<ItemReport>,
    /// Waivers that did not apply (expired, or the item needed none).
    pub waiver_notes: Vec<String>,
}

const SCHEMA_VERSION: u32 = 1;

impl ReleaseReport {
    /// Is every applicable item `pass` or `waived`?
    #[must_use]
    pub fn ready(&self) -> bool {
        self.release_ready
    }

    /// The item with `id`.
    #[must_use]
    pub fn item(&self, id: &str) -> Option<&ItemReport> {
        self.items.iter().find(|i| i.id == id)
    }

    /// The checklist as markdown, grouped by category.
    #[must_use]
    pub fn markdown(&self) -> String {
        let c = self.counts;
        let mut s = format!(
            "# Release-gate checklist ({})\n\n**{}**: {} pass, {} fail, {} unmeasured, {} waived, {} not applicable.\n",
            self.evaluated_on,
            if self.release_ready { "READY" } else { "BLOCKED" },
            c.pass,
            c.fail,
            c.unmeasured,
            c.waived,
            c.not_applicable
        );
        for category in Category::ALL {
            let _ = write!(s, "\n## {}\n\n", category.label());
            for item in self.items.iter().filter(|i| i.category == category) {
                let mark = if item.state.clears() { "x" } else { " " };
                let _ = writeln!(
                    s,
                    "- [{mark}] **{}** `{}`: {}. {}",
                    item.state.as_str(),
                    item.id,
                    item.title,
                    item.detail
                );
            }
        }
        if !self.waiver_notes.is_empty() {
            s.push_str("\n## Waiver notes\n\n");
            for note in &self.waiver_notes {
                let _ = writeln!(s, "- {note}");
            }
        }
        s
    }
}

/// Inputs of [`evaluate`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct GateInputs {
    /// Evidence directory.
    pub evidence: PathBuf,
    /// Repository root (Chromium pin, alert rules, runbooks, previous-release baseline).
    pub repo: PathBuf,
    /// Date the waivers and the restore drill are judged against.
    pub today: NaiveDate,
    /// Whether the model tier changes in this release (enables the model item).
    pub model_tier_changed: bool,
    /// Waivers in force.
    pub waivers: Vec<Waiver>,
}

impl GateInputs {
    /// Inputs without waivers and without a model-tier change.
    #[must_use]
    pub fn new(evidence: impl Into<PathBuf>, repo: impl Into<PathBuf>, today: NaiveDate) -> Self {
        Self {
            evidence: evidence.into(),
            repo: repo.into(),
            today,
            model_tier_changed: false,
            waivers: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Evidence formats
// ---------------------------------------------------------------------------------------------

/// Result of one suite run, recorded by [`record_suite`] into `suites/<id>.json`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SuiteEvidence {
    /// Suite id from [`SUITE_IDS`].
    pub id: String,
    /// The command that ran.
    pub command: Vec<String>,
    /// Process exit code; a signal leaves it empty and fails the suite.
    pub exit_code: Option<i32>,
    /// libtest `passed` over every test binary of the run.
    pub passed: u64,
    /// libtest `failed`.
    pub failed: u64,
    /// libtest `ignored`.
    pub ignored: u64,
    /// Output lines starting with `skipped:` (the tests' marker for a missing prerequisite).
    pub skipped: u64,
    /// Whether the command is a libtest run that must have executed at least one test.
    pub tests_required: bool,
}

/// Sum the `test result:` lines of libtest output as `(passed, failed, ignored)`.
#[must_use]
pub fn parse_libtest(output: &str) -> (u64, u64, u64) {
    let (mut passed, mut failed, mut ignored) = (0u64, 0u64, 0u64);
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("test result: ") else {
            continue;
        };
        for part in rest.split(';') {
            let mut words = part.split_whitespace();
            // the first part reads `ok. 3 passed`, so skip a leading status word
            let mut first = words.next();
            if first.is_some_and(|w| w.ends_with('.')) {
                first = words.next();
            }
            let (Some(n), Some(label)) = (first.and_then(|w| w.parse::<u64>().ok()), words.next()) else {
                continue;
            };
            match label {
                "passed" => passed = passed.saturating_add(n),
                "failed" => failed = failed.saturating_add(n),
                "ignored" => ignored = ignored.saturating_add(n),
                _ => {}
            }
        }
    }
    (passed, failed, ignored)
}

/// Run `command`, capture its result and write `<evidence>/suites/<id>.json`.
///
/// `tests_required` marks a libtest run (the suite must have executed at least one test and
/// ignored none); pass `false` for a tool such as `cargo deny` whose exit status is the result.
/// The command's output is forwarded to this process's stdout and stderr.
///
/// # Errors
/// [`BenchError::Gate`] for an unknown suite id, an empty command or a command that cannot be
/// started; [`BenchError::Io`] / [`BenchError::Json`] when the result cannot be written.
pub fn record_suite(
    evidence: &Path,
    id: &str,
    command: &[String],
    tests_required: bool,
) -> Result<SuiteEvidence, BenchError> {
    if !SUITE_IDS.contains(&id) {
        return Err(BenchError::Gate(format!(
            "unknown suite `{id}`; known: {}",
            SUITE_IDS.join(", ")
        )));
    }
    let (program, args) = command
        .split_first()
        .ok_or_else(|| BenchError::Gate("record: no command given".to_owned()))?;
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| BenchError::Gate(format!("record: run `{program}`: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    {
        use std::io::Write as _;
        // forwarding is best effort: a closed pipe must not lose the recorded result
        let _ = std::io::stdout().write_all(stdout.as_bytes());
        let _ = std::io::stderr().write_all(stderr.as_bytes());
    }
    let (passed, failed, ignored) = parse_libtest(&stdout);
    let skipped = stdout
        .lines()
        .chain(stderr.lines())
        .filter(|l| l.starts_with("skipped:"))
        .count();
    let evidence_record = SuiteEvidence {
        id: id.to_owned(),
        command: command.to_vec(),
        exit_code: output.status.code(),
        passed,
        failed,
        ignored,
        skipped: u64::try_from(skipped).unwrap_or(u64::MAX),
        tests_required,
    };
    let dir = evidence.join("suites");
    std::fs::create_dir_all(&dir).map_err(|e| BenchError::io(&dir, e))?;
    let path = dir.join(format!("{id}.json"));
    let bytes = serde_json::to_vec_pretty(&evidence_record)?;
    std::fs::write(&path, bytes).map_err(|e| BenchError::io(&path, e))?;
    Ok(evidence_record)
}

/// `flake-report.json`: the PR-suite flake rate over a window.
#[derive(Deserialize)]
struct FlakeReport {
    window_days: u32,
    runs: u64,
    flaky_runs: u64,
}

/// `findings.json`: open security findings by severity.
#[derive(Deserialize)]
struct Findings {
    open_s1: u64,
    open_s2: u64,
}

/// `run-to-run.json`: different-seed Jaccard of this and of the previous release.
#[derive(Deserialize)]
struct RunToRun {
    different_seed_jaccard: f64,
    previous_release_different_seed_jaccard: f64,
}

/// `restore-drill.json`: the last completed restore drill.
#[derive(Deserialize)]
struct RestoreDrill {
    completed_on: String,
}

#[derive(Deserialize)]
struct SoakView {
    elapsed_s: f64,
    store: String,
    cycles: u64,
    failures: u64,
    actions: u64,
    faults: Vec<serde_json::Value>,
    verdict: SoakVerdict,
    #[serde(default)]
    failed_cycles: Vec<SoakCycle>,
}

#[derive(Deserialize)]
struct SoakVerdict {
    verdict: String,
    #[serde(default)]
    reasons: Vec<String>,
}

#[derive(Deserialize)]
struct SoakCycle {
    #[serde(default)]
    stuck_intended: u64,
    #[serde(default)]
    unreconciled_unknown: u64,
}

/// `bench/baselines/release-base.json`: facts of the previous release.
#[derive(Deserialize)]
struct ReleaseBase {
    chromium_pin: PinView,
}

#[derive(Deserialize, PartialEq, Eq)]
struct PinView {
    version: String,
    sha256: String,
}

// ---------------------------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------------------------

enum Loaded<T> {
    Absent,
    Bad(String),
    Ok(T),
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Loaded<T> {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Absent,
        Err(e) => Loaded::Bad(format!("read {}: {e}", path.display())),
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(v) => Loaded::Ok(v),
            Err(e) => Loaded::Bad(format!("{}: {e}", path.display())),
        },
    }
}

/// Outcome of one evaluator.
enum Raw {
    Pass(String),
    Fail(String),
    Unmeasured(String),
}

struct Ctx<'a> {
    inputs: &'a GateInputs,
    cards: Vec<Scorecard>,
    card_errors: Vec<String>,
    g1: Loaded<G1Report>,
}

type CardKey = (String, u64, String, &'static str);

impl<'a> Ctx<'a> {
    fn load(inputs: &'a GateInputs) -> Self {
        let g1 = load_json::<G1Report>(&inputs.evidence.join("g1-report.json"));
        let mut seen: BTreeSet<CardKey> = BTreeSet::new();
        let mut cards = Vec::new();
        let mut card_errors = Vec::new();
        let mut push = |card: Scorecard| {
            let key = (
                card.fixture.clone(),
                card.seed,
                card.variant.clone(),
                card.profile.as_str(),
            );
            if seen.insert(key) {
                cards.push(card);
            }
        };
        let dir = inputs.evidence.join("scorecards");
        if let Ok(read) = std::fs::read_dir(&dir) {
            let mut files: Vec<PathBuf> = read
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect();
            files.sort();
            for file in files {
                match load_json::<Scorecard>(&file) {
                    Loaded::Ok(card) => push(card),
                    Loaded::Bad(e) => card_errors.push(e),
                    Loaded::Absent => {}
                }
            }
        }
        match &g1 {
            Loaded::Ok(report) => report.scorecards.iter().cloned().for_each(&mut push),
            Loaded::Bad(e) => card_errors.push(e.clone()),
            Loaded::Absent => {}
        }
        Self {
            inputs,
            cards,
            card_errors,
            g1,
        }
    }

    fn evidence_path(&self, rel: &str) -> PathBuf {
        self.inputs.evidence.join(rel)
    }

    fn repo_path(&self, rel: &str) -> PathBuf {
        self.inputs.repo.join(rel)
    }

    /// Scorecards of the fixture that implements catalog row `row` (`"G26"`).
    fn cards_of<'s>(&'s self, row: &str) -> impl Iterator<Item = &'s Scorecard> + 's {
        let id = catalog_row(row);
        self.cards.iter().filter(move |c| Some(c.fixture.as_str()) == id)
    }

    /// Fail text when a scorecard file could not be read.
    fn card_error(&self) -> Option<Raw> {
        self.card_errors
            .first()
            .map(|e| Raw::Fail(format!("unreadable scorecard evidence: {e}")))
    }
}

/// Load `rel` from the evidence directory or return the `Raw` that ends the evaluator.
macro_rules! evidence {
    ($ctx:expr, $rel:expr, $ty:ty) => {
        match load_json::<$ty>(&$ctx.evidence_path($rel)) {
            Loaded::Ok(v) => v,
            Loaded::Absent => return Raw::Unmeasured(format!("{} not found", $rel)),
            Loaded::Bad(e) => return Raw::Fail(format!("unreadable evidence: {e}")),
        }
    };
}

/// Return the scorecard error, if any.
macro_rules! cards_ok {
    ($ctx:expr) => {
        if let Some(raw) = $ctx.card_error() {
            return raw;
        }
    };
}

#[allow(clippy::cast_precision_loss)] // counts stay far below 2^53
fn ratio(num: u64, den: u64) -> f64 {
    num as f64 / den as f64
}

// ---------------------------------------------------------------------------------------------
// Evaluators
// ---------------------------------------------------------------------------------------------

const PROFILES: [SafetyProfile; 3] = [
    SafetyProfile::ReadOnly,
    SafetyProfile::TestEnvironment,
    SafetyProfile::AuthorizedSecurityTest,
];

fn eval_suite(c: &Ctx<'_>, id: &str) -> Raw {
    let rel = format!("suites/{id}.json");
    let s = evidence!(c, &rel, SuiteEvidence);
    if s.id != id {
        return Raw::Fail(format!("{rel} records suite `{}`", s.id));
    }
    if s.exit_code != Some(0) {
        return Raw::Fail(format!("`{}` exited {:?}", s.command.join(" "), s.exit_code));
    }
    if s.failed > 0 {
        return Raw::Fail(format!("{} tests failed", s.failed));
    }
    if s.skipped > 0 {
        return Raw::Fail(format!("{} tests skipped for a missing prerequisite", s.skipped));
    }
    if s.tests_required {
        if s.passed == 0 {
            return Raw::Fail("the run executed no tests".to_owned());
        }
        if s.ignored > 0 {
            return Raw::Fail(format!("{} tests ignored", s.ignored));
        }
        return Raw::Pass(format!("{} tests passed", s.passed));
    }
    Raw::Pass("exit 0".to_owned())
}

fn eval_unauthorized(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let mut missing = Vec::new();
    let mut bad = Vec::new();
    let mut runs = 0u64;
    for row in ["G19", "G21"] {
        for profile in PROFILES {
            let matching: Vec<&Scorecard> = c.cards_of(row).filter(|k| k.profile == profile).collect();
            if matching.is_empty() {
                missing.push(format!("{row}/{}", profile.as_str()));
            }
            for card in matching {
                runs += 1;
                if card.safety.unauthorized != 0 || card.safety.unauthorized_action_rate != 0.0 {
                    bad.push(format!(
                        "{row}/{} seed {}: {} unauthorized of {}",
                        profile.as_str(),
                        card.seed,
                        card.safety.unauthorized,
                        card.safety.executed
                    ));
                }
            }
        }
    }
    if !bad.is_empty() {
        return Raw::Fail(bad.join("; "));
    }
    if !missing.is_empty() {
        return Raw::Unmeasured(format!("no scorecard for {}", missing.join(", ")));
    }
    Raw::Pass(format!(
        "0 unauthorized actions over {runs} runs (G19, G21, every profile)"
    ))
}

fn eval_mutants(c: &Ctx<'_>) -> Raw {
    let doc = evidence!(c, "mutants-safety/outcomes.json", serde_json::Value);
    let Some(outcomes) = doc.get("outcomes").and_then(serde_json::Value::as_array) else {
        return Raw::Fail("outcomes.json has no `outcomes` array".to_owned());
    };
    let (mut caught, mut missed) = (0u64, 0u64);
    for outcome in outcomes {
        // the baseline run carries a non-object scenario; only mutants count
        if !outcome
            .get("scenario")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|s| s.contains_key("Mutant"))
        {
            continue;
        }
        match outcome.get("summary").and_then(serde_json::Value::as_str) {
            // a timeout means the mutation hung the suite: caught
            Some("CaughtMutant" | "Timeout") => caught += 1,
            Some("MissedMutant") => missed += 1,
            _ => {}
        }
    }
    let viable = caught + missed;
    if viable == 0 {
        return Raw::Fail("no viable mutants".to_owned());
    }
    let detail = format!(
        "{caught} of {viable} viable crawlx-safety mutants caught ({:.1} %, need {MUTANTS_MIN_PERCENT} %)",
        ratio(caught, viable) * 100.0
    );
    if caught * 100 >= viable * MUTANTS_MIN_PERCENT {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_findings(c: &Ctx<'_>) -> Raw {
    let f = evidence!(c, "findings.json", Findings);
    let detail = format!("{} open S1, {} open S2", f.open_s1, f.open_s2);
    if f.open_s1 == 0 && f.open_s2 == 0 {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_repeated_non_idempotent(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let measured: Vec<_> = c.cards.iter().filter_map(|k| k.unknown.map(|u| (k, u))).collect();
    if measured.is_empty() {
        return Raw::Unmeasured("no scorecard carries unknown-outcome metrics".to_owned());
    }
    let repeated: u64 = measured.iter().map(|(_, u)| u.repeated_non_idempotent).sum();
    let detail = format!(
        "{repeated} repeated executions over {} scorecards",
        measured.len()
    );
    if repeated == 0 {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_worker_kill(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let report = match &c.g1 {
        Loaded::Ok(r) => r,
        Loaded::Absent => return Raw::Unmeasured("g1-report.json not found".to_owned()),
        Loaded::Bad(e) => return Raw::Fail(format!("unreadable evidence: {e}")),
    };
    let chaos_passed = report.chaos.as_ref().is_some_and(ChaosEvidence::passed);
    if !chaos_passed {
        return Raw::Fail("chaos suites missing, stale for this build, incomplete or failed".to_owned());
    }
    let measured: Vec<_> = c.cards.iter().filter_map(|k| k.unknown).collect();
    if measured.is_empty() {
        return Raw::Unmeasured("no scorecard carries unknown-outcome metrics".to_owned());
    }
    let unreconciled: u64 = measured
        .iter()
        .map(|u| u.unknown_total.saturating_sub(u.reconciled))
        .sum();
    let repeated: u64 = measured.iter().map(|u| u.repeated_non_idempotent).sum();
    let detail = format!(
        "chaos suites passed; {unreconciled} unknown outcomes left unreconciled, {repeated} repeated effects"
    );
    if unreconciled == 0 && repeated == 0 {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_state_merges(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let states: Vec<_> = c.cards_of("G26").filter_map(|k| k.states).collect();
    if states.is_empty() {
        return Raw::Unmeasured("no G26 scorecard with state metrics".to_owned());
    }
    let hiding: u64 = states.iter().map(|s| s.merges_hiding_actions).sum();
    let split = states.iter().map(|s| s.false_split_rate).fold(0.0, f64::max);
    let detail = format!(
        "{hiding} merges hiding a reachable action (need 0); false split {split:.4} (max {STATE_FALSE_SPLIT_MAX})"
    );
    if hiding == 0 && split <= STATE_FALSE_SPLIT_MAX {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_identity(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let mut missing = Vec::new();
    let (mut collision, mut split) = (0.0f64, 0.0f64);
    for row in ["G02", "G06"] {
        let ids: Vec<_> = c.cards_of(row).filter_map(|k| k.identity).collect();
        if ids.is_empty() {
            missing.push(row);
        }
        for id in ids {
            collision = collision.max(id.collision_rate);
            split = split.max(id.split_rate);
        }
    }
    if !missing.is_empty() {
        return Raw::Unmeasured(format!("no identity metrics for {}", missing.join(", ")));
    }
    let detail = format!(
        "collision {collision:.4} (max {IDENTITY_COLLISION_MAX}), split {split:.4} (max {IDENTITY_SPLIT_MAX}) on G02/G06"
    );
    if collision <= IDENTITY_COLLISION_MAX && split <= IDENTITY_SPLIT_MAX {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_targets(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let (mut tp, mut fp, mut fn_) = (0u64, 0u64, 0u64);
    for card in &c.cards {
        if let Some(p) = card.targets.by_mechanism.get("ax") {
            tp += p.tp;
            fp += p.fp;
            fn_ += p.fn_;
        }
    }
    if tp + fn_ == 0 || tp + fp == 0 {
        return Raw::Unmeasured("no AX-addressable targets scored".to_owned());
    }
    let recall = ratio(tp, tp + fn_);
    let precision = ratio(tp, tp + fp);
    let detail = format!(
        "AX recall {recall:.4} (min {TARGET_RECALL_MIN}), precision {precision:.4} (min {TARGET_PRECISION_MIN})"
    );
    if recall >= TARGET_RECALL_MIN && precision >= TARGET_PRECISION_MIN {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_enablement(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let replay: Vec<f64> = c
        .cards_of("G11")
        .filter_map(|k| k.enablement.as_ref().and_then(|e| e.replay_success))
        .collect();
    let mut false_edges = Vec::new();
    let mut missing = Vec::new();
    if replay.is_empty() {
        missing.push("G11 replay success");
    }
    for row in ["G09", "G10"] {
        let rates: Vec<f64> = c
            .cards_of(row)
            .filter_map(|k| k.enablement.as_ref().and_then(|e| e.false_edge_rate))
            .collect();
        if rates.is_empty() {
            missing.push(if row == "G09" {
                "G09 false edge rate"
            } else {
                "G10 false edge rate"
            });
        }
        false_edges.extend(rates);
    }
    let worst_replay = replay.iter().copied().fold(f64::INFINITY, f64::min);
    let worst_edge = false_edges.iter().copied().fold(0.0, f64::max);
    let bad = (!replay.is_empty() && worst_replay < ENABLEMENT_REPLAY_MIN)
        || worst_edge > FALSE_ENABLEMENT_EDGE_MAX;
    if bad {
        return Raw::Fail(format!(
            "G11 replay success {worst_replay:.4} (min {ENABLEMENT_REPLAY_MIN}), G09/G10 false edge rate {worst_edge:.4} (max {FALSE_ENABLEMENT_EDGE_MAX})"
        ));
    }
    if !missing.is_empty() {
        return Raw::Unmeasured(format!("no scorecard value for {}", missing.join(", ")));
    }
    Raw::Pass(format!(
        "G11 replay success {worst_replay:.4}, G09/G10 false edge rate {worst_edge:.4}"
    ))
}

fn eval_quiescence(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let exempt: Vec<&str> = QUIESCENCE_EXEMPT_ROWS
        .iter()
        .filter_map(|r| catalog_row(r))
        .collect();
    let rates: Vec<f64> = c
        .cards
        .iter()
        .filter(|k| !exempt.contains(&k.fixture.as_str()))
        .filter_map(|k| k.quiescence_timeout_rate)
        .collect();
    if rates.is_empty() {
        return Raw::Unmeasured("no non-adversarial scorecard measured quiescence".to_owned());
    }
    let worst = rates.iter().copied().fold(0.0, f64::max);
    let detail = format!(
        "worst quiescence timeout rate {worst:.4} over {} scorecards (max {QUIESCENCE_TIMEOUT_MAX})",
        rates.len()
    );
    if worst <= QUIESCENCE_TIMEOUT_MAX {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_trusted_lane(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let mut worst = f64::INFINITY;
    let mut measured = 0usize;
    for lanes in c.cards.iter().filter_map(|k| k.lanes) {
        let total = lanes.trusted + lanes.diagnostic;
        if total == 0 {
            continue;
        }
        measured += 1;
        worst = worst.min(ratio(lanes.trusted, total));
    }
    if measured == 0 {
        return Raw::Unmeasured("no scorecard carries lane counts".to_owned());
    }
    let detail = format!(
        "lowest trusted-lane share {worst:.4} over {measured} scorecards (min {TRUSTED_LANE_SHARE_MIN})"
    );
    if worst >= TRUSTED_LANE_SHARE_MIN {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_same_seed(c: &Ctx<'_>) -> Raw {
    cards_ok!(c);
    let values: Vec<f64> = c.cards.iter().filter_map(|k| k.run_to_run_jaccard).collect();
    if values.is_empty() {
        return Raw::Unmeasured("no scorecard carries a same-seed Jaccard".to_owned());
    }
    let lowest = values.iter().copied().fold(f64::INFINITY, f64::min);
    let detail = format!(
        "lowest same-seed Jaccard {lowest:.4} over {} scorecards (need 1.0)",
        values.len()
    );
    if values.iter().all(|v| *v == 1.0) {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_different_seed(c: &Ctx<'_>) -> Raw {
    let r = evidence!(c, "run-to-run.json", RunToRun);
    let drop = r.previous_release_different_seed_jaccard - r.different_seed_jaccard;
    let detail = format!(
        "different-seed Jaccard {:.4} against {:.4} in the previous release (drop at most {DIFFERENT_SEED_JACCARD_MAX_DROP})",
        r.different_seed_jaccard, r.previous_release_different_seed_jaccard
    );
    if drop <= DIFFERENT_SEED_JACCARD_MAX_DROP + JACCARD_EPSILON {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_coverage(c: &Ctx<'_>) -> Raw {
    let p = evidence!(c, "coverage-paired.json", PairedComparison);
    if !p.metric.starts_with("coverage") || p.direction != Direction::HigherIsBetter {
        return Raw::Fail(format!(
            "coverage-paired.json compares `{}`, not a higher-is-better coverage metric",
            p.metric
        ));
    }
    let detail = format!(
        "{} paired difference vs the previous release {:+.4}, {:.0} % CI [{:+.4}, {:+.4}] over {} pairs",
        p.metric,
        p.bootstrap.mean_diff,
        p.bootstrap.level * 100.0,
        p.bootstrap.lo,
        p.bootstrap.hi,
        p.bootstrap.pairs
    );
    // the interval must not reach below zero: a decrease is excluded
    if p.bootstrap.lo >= 0.0 {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_soak(c: &Ctx<'_>) -> Raw {
    let s = evidence!(c, "soak-report.json", SoakView);
    let mut problems = Vec::new();
    if s.verdict.verdict == "fail" {
        problems.push(format!("verdict fail: {}", s.verdict.reasons.join("; ")));
    }
    if s.failures > 0 {
        problems.push(format!("{} failed cycles", s.failures));
    }
    let stuck: u64 = s.failed_cycles.iter().map(|k| k.stuck_intended).sum();
    let unknown: u64 = s.failed_cycles.iter().map(|k| k.unreconciled_unknown).sum();
    if stuck > 0 {
        problems.push(format!("{stuck} actions stuck in intended"));
    }
    if unknown > 0 {
        problems.push(format!("{unknown} unreconciled unknown actions"));
    }
    if s.cycles == 0 || s.actions == 0 {
        problems.push("the soak journaled no actions".to_owned());
    }
    if !problems.is_empty() {
        return Raw::Fail(problems.join("; "));
    }
    let mut short = Vec::new();
    if s.verdict.verdict != "pass" {
        short.push(format!("verdict {}", s.verdict.verdict));
    }
    if s.elapsed_s < SOAK_MIN_SECONDS {
        short.push(format!("ran {:.1} h, need 24 h", s.elapsed_s / 3600.0));
    }
    if s.store != "postgres" {
        short.push(format!("{} store, need postgres", s.store));
    }
    if s.faults.is_empty() {
        short.push("no scheduled faults injected".to_owned());
    }
    if !short.is_empty() {
        return Raw::Unmeasured(format!("soak is not release evidence: {}", short.join("; ")));
    }
    Raw::Pass(format!(
        "{} cycles, {} actions, {} faults over {:.1} h, no stuck or unreconciled action",
        s.cycles,
        s.actions,
        s.faults.len(),
        s.elapsed_s / 3600.0
    ))
}

fn eval_chaos(c: &Ctx<'_>) -> Raw {
    match &c.g1 {
        Loaded::Absent => Raw::Unmeasured("g1-report.json not found".to_owned()),
        Loaded::Bad(e) => Raw::Fail(format!("unreadable evidence: {e}")),
        Loaded::Ok(report) => match &report.chaos {
            None => Raw::Unmeasured("g1-report.json carries no chaos evidence".to_owned()),
            Some(chaos) if chaos.passed() => Raw::Pass(format!("{} chaos suites passed", chaos.suites.len())),
            Some(_) => Raw::Fail("chaos suites stale for this build, incomplete or failed".to_owned()),
        },
    }
}

fn eval_flake(c: &Ctx<'_>) -> Raw {
    let f = evidence!(c, "flake-report.json", FlakeReport);
    if f.runs == 0 {
        return Raw::Unmeasured("flake report covers no runs".to_owned());
    }
    if f.window_days < FLAKE_WINDOW_DAYS {
        return Raw::Unmeasured(format!(
            "flake report window is {} days, need {FLAKE_WINDOW_DAYS}",
            f.window_days
        ));
    }
    let detail = format!(
        "{} flaky of {} runs over {} days ({:.3} %, limit below {FLAKE_RATE_LIMIT_PERCENT} %)",
        f.flaky_runs,
        f.runs,
        f.window_days,
        ratio(f.flaky_runs, f.runs) * 100.0
    );
    if f.flaky_runs.saturating_mul(100) < f.runs.saturating_mul(FLAKE_RATE_LIMIT_PERCENT) {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

fn eval_model(c: &Ctx<'_>) -> Raw {
    let report = evidence!(c, "g3-report.json", crate::gates::G3Report);
    let verdict = crate::gates::evaluate_g3(&report);
    if !verdict.passed() {
        let failed: Vec<&str> = verdict
            .checks
            .iter()
            .filter(|k| !k.passed)
            .map(|k| k.name.as_str())
            .collect();
        return Raw::Fail(format!("calibration gate failed: {}", failed.join(", ")));
    }
    match eval_suite(c, "model_breaker_outage") {
        Raw::Pass(d) => Raw::Pass(format!(
            "calibration and shadow gates met; breaker outage suite: {d}"
        )),
        other => other,
    }
}

fn read_pin(path: &Path) -> Result<PinView, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let table: toml::Table = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let chromium = table
        .get("chromium")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("{}: no [chromium] table", path.display()))?;
    let field = |name: &str| {
        chromium
            .get(name)
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("{}: chromium.{name} missing", path.display()))
    };
    Ok(PinView {
        version: field("version")?,
        sha256: field("sha256")?,
    })
}

fn eval_chromium_pin(c: &Ctx<'_>) -> Raw {
    let pin = match read_pin(&c.repo_path("chromium-pin.toml")) {
        Ok(p) => p,
        Err(e) => return Raw::Unmeasured(e),
    };
    let base_path = c.repo_path("bench/baselines/release-base.json");
    let base = match load_json::<ReleaseBase>(&base_path) {
        Loaded::Ok(b) => b.chromium_pin,
        Loaded::Absent => {
            return Raw::Unmeasured(
                "bench/baselines/release-base.json (previous release pin) not found".to_owned(),
            )
        }
        Loaded::Bad(e) => return Raw::Fail(format!("unreadable baseline: {e}")),
    };
    if pin == base {
        return Raw::Pass(format!(
            "Chromium pin {} unchanged since the previous release",
            pin.version
        ));
    }
    let detail = format!("Chromium pin moved from {} to {}", base.version, pin.version);
    match eval_suite(c, "chromium_upgrade") {
        Raw::Pass(d) => Raw::Pass(format!("{detail}; upgrade suite: {d}")),
        Raw::Unmeasured(d) => Raw::Unmeasured(format!("{detail}; {d}")),
        Raw::Fail(d) => Raw::Fail(format!("{detail}; upgrade suite: {d}")),
    }
}

fn eval_restore_drill(c: &Ctx<'_>) -> Raw {
    let d = evidence!(c, "restore-drill.json", RestoreDrill);
    let Ok(done) = NaiveDate::parse_from_str(&d.completed_on, "%Y-%m-%d") else {
        return Raw::Fail(format!(
            "restore drill date `{}` is not YYYY-MM-DD",
            d.completed_on
        ));
    };
    let age = (c.inputs.today - done).num_days();
    let detail =
        format!("restore drill completed {done}, {age} days ago (limit {RESTORE_DRILL_MAX_AGE_DAYS})");
    if age < 0 {
        Raw::Fail(format!("restore drill is dated in the future: {done}"))
    } else if age <= RESTORE_DRILL_MAX_AGE_DAYS {
        Raw::Pass(detail)
    } else {
        Raw::Fail(detail)
    }
}

/// Every `crawlx_*` family name the telemetry catalog exports, with the `_bucket`, `_count` and
/// `_sum` series of histograms.
#[must_use]
pub fn exported_metric_names() -> BTreeSet<String> {
    use crawlx_telemetry::metrics::catalog::{self, MetricKind};
    let mut out = BTreeSet::new();
    for def in catalog::all() {
        let base = def.prometheus_name();
        if def.kind == MetricKind::Histogram {
            for suffix in ["_bucket", "_count", "_sum"] {
                out.insert(format!("{base}{suffix}"));
            }
        }
        out.insert(base);
    }
    out
}

/// Findings of [`check_runbook_links`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct RunbookCheck {
    /// Alert rules read.
    pub alerts: usize,
    /// Distinct metric families the rule expressions reference.
    pub metrics: usize,
    /// Runbook anchors the `runbook` annotations reference.
    pub runbook_refs: usize,
    /// One line per defect.
    pub problems: Vec<String>,
}

fn crawlx_idents(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(pos) = text[from..].find("crawlx_") {
        let start = from + pos;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        out.insert(text[start..end].to_owned());
        from = end;
    }
    out
}

/// GitHub-style anchor of a markdown heading.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Cross-check the alert rules against the runbooks and the metric catalog: every metric the
/// rule expressions reference is exported by the catalog, every `runbook` annotation points at
/// an anchor of `runbooks_md`, and every alert has its alert card (a `## N. AlertName` heading).
///
/// The rule file is scanned line by line (alert names, `expr` blocks and `runbook` annotations),
/// which is exact for the layout `deploy/alerts/crawlx-rules.yaml` uses.
#[must_use]
pub fn check_runbook_links(rules_yaml: &str, runbooks_md: &str, exported: &BTreeSet<String>) -> RunbookCheck {
    let mut anchors = BTreeSet::new();
    let mut cards = BTreeSet::new();
    for line in runbooks_md.lines() {
        if let Some(pos) = line.find("<a id=\"") {
            if let Some(end) = line[pos + 7..].find('"') {
                anchors.insert(line[pos + 7..pos + 7 + end].to_owned());
            }
        }
        if line.starts_with('#') {
            let text = line.trim_start_matches('#');
            anchors.insert(slug(text));
            if let Some((_, name)) = text.trim().split_once(". ") {
                cards.insert(name.trim().to_owned());
            }
        }
    }
    let mut check = RunbookCheck::default();
    let mut metrics = BTreeSet::new();
    let mut current: Option<String> = None;
    let mut in_expr = false;
    for raw in rules_yaml.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix("- alert:") {
            let name = name.trim().to_owned();
            check.alerts += 1;
            if !cards.contains(&name) {
                check
                    .problems
                    .push(format!("{name}: no alert card in runbooks.md"));
            }
            current = Some(name);
            in_expr = false;
            continue;
        }
        let alert = current.as_deref().unwrap_or("(no alert)");
        if let Some(rest) = line.strip_prefix("expr:") {
            in_expr = true;
            metrics.extend(crawlx_idents(rest));
            check_metrics(alert, rest, exported, &mut check.problems);
            continue;
        }
        if ["for:", "labels:", "annotations:", "keep_firing_for:"]
            .iter()
            .any(|k| line.starts_with(k))
        {
            in_expr = false;
        }
        if in_expr {
            metrics.extend(crawlx_idents(line));
            check_metrics(alert, line, exported, &mut check.problems);
        }
        if let Some(refs) = line.strip_prefix("runbook:") {
            for target in refs.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                check.runbook_refs += 1;
                let anchor = target.split_once('#').map(|(_, a)| a);
                match anchor {
                    Some(a) if anchors.contains(a) => {}
                    Some(a) => check
                        .problems
                        .push(format!("{alert}: runbook anchor `#{a}` does not exist")),
                    None => check
                        .problems
                        .push(format!("{alert}: runbook `{target}` has no anchor")),
                }
            }
        }
    }
    check.metrics = metrics.len();
    check
}

fn check_metrics(alert: &str, text: &str, exported: &BTreeSet<String>, problems: &mut Vec<String>) {
    for m in crawlx_idents(text) {
        if !exported.contains(&m) {
            problems.push(format!("{alert}: `{m}` is not in the telemetry metric catalog"));
        }
    }
}

fn eval_runbooks(c: &Ctx<'_>) -> Raw {
    let read = |rel: &str| std::fs::read_to_string(c.repo_path(rel));
    let (rules, runbooks) = match (
        read("deploy/alerts/crawlx-rules.yaml"),
        read("docs/ops/runbooks.md"),
    ) {
        (Ok(r), Ok(b)) => (r, b),
        (Err(e), _) | (_, Err(e)) => {
            return Raw::Unmeasured(format!("alert rules or runbooks not readable: {e}"))
        }
    };
    let check = check_runbook_links(&rules, &runbooks, &exported_metric_names());
    if check.alerts == 0 {
        return Raw::Fail("deploy/alerts/crawlx-rules.yaml defines no alert".to_owned());
    }
    if check.problems.is_empty() {
        Raw::Pass(format!(
            "{} alerts, {} metric families and {} runbook anchors validated against the catalog and runbooks.md",
            check.alerts, check.metrics, check.runbook_refs
        ))
    } else {
        Raw::Fail(check.problems.join("; "))
    }
}

// ---------------------------------------------------------------------------------------------
// Checklist table
// ---------------------------------------------------------------------------------------------

enum Eval {
    /// A suite result `suites/<id>.json`, the id being the item id.
    Suite,
    Fn(fn(&Ctx<'_>) -> Raw),
}

struct ItemSpec {
    id: &'static str,
    category: Category,
    title: &'static str,
    waivable: bool,
    model_only: bool,
    evidence: &'static [&'static str],
    eval: Eval,
}

const fn spec(
    id: &'static str,
    category: Category,
    title: &'static str,
    evidence: &'static [&'static str],
    eval: Eval,
) -> ItemSpec {
    ItemSpec {
        id,
        category,
        title,
        waivable: false,
        model_only: false,
        evidence,
        eval,
    }
}

const SCORECARDS: &str = "scorecards/*.json";
const G1_REPORT: &str = "g1-report.json";

use Category::{Compatibility, Correctness, Model, Operations, PerformanceReliability, SafetySecurity};

const ITEMS: &[ItemSpec] = &[
    spec(
        "unauthorized_action_rate",
        SafetySecurity,
        "unauthorized_action_rate = 0 on G19 and G21, every profile",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_unauthorized),
    ),
    spec(
        "ssrf_matrix",
        SafetySecurity,
        "SSRF matrix: zero connections to denied classes on both planes, rebinding and redirect-chain rows, G29",
        &["suites/ssrf_matrix.json"],
        Eval::Suite,
    ),
    spec(
        "scope_escape",
        SafetySecurity,
        "scope-escape suite passes; out-of-scope denied in all profiles",
        &["suites/scope_escape.json"],
        Eval::Suite,
    ),
    spec(
        "secret_canary_zdr",
        SafetySecurity,
        "secret canary and ZDR checks: zero leaks",
        &["suites/secret_canary_zdr.json"],
        Eval::Suite,
    ),
    spec(
        "mutants_safety",
        SafetySecurity,
        "cargo-mutants score on crawlx-safety >= 95 %",
        &["mutants-safety/outcomes.json"],
        Eval::Fn(eval_mutants),
    ),
    spec(
        "cargo_deny",
        SafetySecurity,
        "cargo-deny clean",
        &["suites/cargo_deny.json"],
        Eval::Suite,
    ),
    spec(
        "security_findings",
        SafetySecurity,
        "no open S1/S2 security finding",
        &["findings.json"],
        Eval::Fn(eval_findings),
    ),
    spec(
        "repeated_non_idempotent",
        SafetySecurity,
        "repeated non-idempotent executions of one action_id = 0 across chaos and soak",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_repeated_non_idempotent),
    ),
    spec(
        "worker_kill_reconciled",
        Correctness,
        "worker kill between intent and outcome: unknown then reconciled, never a duplicate effect",
        &[G1_REPORT, SCORECARDS],
        Eval::Fn(eval_worker_kill),
    ),
    spec(
        "state_false_merges",
        Correctness,
        "state false merges hiding a reachable action = 0 on G26; false split <= 5 %",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_state_merges),
    ),
    spec(
        "identity_stability",
        Correctness,
        "identity collision <= 0.5 % and split <= 2 % on G02 and G06",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_identity),
    ),
    spec(
        "interactive_targets",
        Correctness,
        "interactive-target recall >= 0.95 and precision >= 0.95 on AX-addressable fixtures",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_targets),
    ),
    spec(
        "enablement",
        Correctness,
        "enablement replay success >= 0.9 on G11; false enablement edge rate <= 10 % on G09 and G10",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_enablement),
    ),
    spec(
        "stale_proposal_executions",
        Correctness,
        "stale-proposal executions = 0 (G25)",
        &["suites/stale_proposal_executions.json"],
        Eval::Suite,
    ),
    spec(
        "quiescence_timeout_rate",
        Correctness,
        "quiescence timeout rate <= 2 % on non-adversarial fixtures",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_quiescence),
    ),
    spec(
        "trusted_lane_share",
        Correctness,
        "trusted-lane share >= 99 % of actions",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_trusted_lane),
    ),
    spec(
        "same_seed_jaccard",
        Correctness,
        "same-seed Jaccard = 1.0 on deterministic fixtures",
        &[SCORECARDS, G1_REPORT],
        Eval::Fn(eval_same_seed),
    ),
    spec(
        "different_seed_jaccard",
        Correctness,
        "different-seed Jaccard not worse than the previous release by more than 0.03",
        &["run-to-run.json"],
        Eval::Fn(eval_different_seed),
    ),
    spec(
        "action_context_coverage",
        Correctness,
        "action-context coverage not worse than the previous release (paired CI excludes a decrease)",
        &["coverage-paired.json"],
        Eval::Fn(eval_coverage),
    ),
    spec(
        "differential_extraction",
        Compatibility,
        "differential extraction and URL-filter suites pass",
        &["suites/differential_extraction.json"],
        Eval::Suite,
    ),
    spec(
        "snapshots_unchanged",
        Compatibility,
        "CrawlerGym, extraction snapshots and API schema snapshots unchanged",
        &["suites/snapshots_unchanged.json"],
        Eval::Suite,
    ),
    ItemSpec {
        waivable: true,
        ..spec(
            "criterion_gates",
            PerformanceReliability,
            "every Criterion gate within target (ci/bench-gate.sh exits 0)",
            &["suites/criterion_gates.json"],
            Eval::Suite,
        )
    },
    spec(
        "soak_invariants",
        PerformanceReliability,
        "24 h soak with scheduled faults: invariants hold, no stuck intended row, no unreconciled unknown",
        &["soak-report.json"],
        Eval::Fn(eval_soak),
    ),
    spec(
        "chaos_suite",
        PerformanceReliability,
        "chaos suites pass (completed worker and CLI suite artifacts, current build)",
        &[G1_REPORT],
        Eval::Fn(eval_chaos),
    ),
    spec(
        "chaos_slo",
        PerformanceReliability,
        "DB failover and lease-expiry SLO checks pass",
        &["suites/chaos_slo.json"],
        Eval::Suite,
    ),
    spec(
        "flake_rate",
        PerformanceReliability,
        "PR-suite flake rate < 1 % over 30 days",
        &["flake-report.json"],
        Eval::Fn(eval_flake),
    ),
    ItemSpec {
        model_only: true,
        ..spec(
            "model_tier",
            Model,
            "ONNX parity, calibration (ECE <= 0.05) and shadow-mode gates met; breaker outage test passes",
            &["g3-report.json", "suites/model_breaker_outage.json"],
            Eval::Fn(eval_model),
        )
    },
    spec(
        "chromium_pin",
        Operations,
        "chromium-pin.toml unchanged since the previous release, or the Chromium-upgrade suite passed",
        &["chromium-pin.toml", "bench/baselines/release-base.json", "suites/chromium_upgrade.json"],
        Eval::Fn(eval_chromium_pin),
    ),
    spec(
        "migrations_tested",
        Operations,
        "migrations tested up/down against production-shaped data",
        &["suites/migrations_tested.json"],
        Eval::Suite,
    ),
    spec(
        "restore_drill",
        Operations,
        "restore drill completed in the last 90 days",
        &["restore-drill.json"],
        Eval::Fn(eval_restore_drill),
    ),
    spec(
        "runbook_catalog",
        Operations,
        "runbook links and alert names validated against the shipped telemetry metric catalog",
        &["deploy/alerts/crawlx-rules.yaml", "docs/ops/runbooks.md"],
        Eval::Fn(eval_runbooks),
    ),
];

/// Ids of the checklist items, in checklist order.
pub fn item_ids() -> impl Iterator<Item = &'static str> {
    ITEMS.iter().map(|i| i.id)
}

/// Ids of the items a [`Waiver`] may cover.
pub fn waivable_item_ids() -> impl Iterator<Item = &'static str> {
    ITEMS.iter().filter(|i| i.waivable).map(|i| i.id)
}

fn expiry(w: &Waiver) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(&w.expires, "%Y-%m-%d")
        .map_err(|e| format!("waiver for `{}`: expires `{}`: {e}", w.item, w.expires))
}

fn validate_waivers(waivers: &[Waiver]) -> Result<(), BenchError> {
    for w in waivers {
        let Some(spec) = ITEMS.iter().find(|i| i.id == w.item) else {
            return Err(BenchError::Gate(format!("waiver for unknown item `{}`", w.item)));
        };
        if !spec.waivable {
            return Err(BenchError::Gate(format!(
                "item `{}` cannot be waived (waivable: {})",
                w.item,
                waivable_item_ids().collect::<Vec<_>>().join(", ")
            )));
        }
        if w.owner.trim().is_empty() || w.reason.trim().is_empty() {
            return Err(BenchError::Gate(format!(
                "waiver for `{}` needs an owner and a reason",
                w.item
            )));
        }
        expiry(w).map_err(BenchError::Gate)?;
    }
    Ok(())
}

/// Evaluate the checklist.
///
/// # Errors
/// [`BenchError::Gate`] when a waiver is malformed: unknown item, an item that cannot be
/// waived, a missing owner or reason, or an expiry that is not `YYYY-MM-DD`. Unreadable
/// evidence is not an error; it fails the item that reads it.
pub fn evaluate(inputs: &GateInputs) -> Result<ReleaseReport, BenchError> {
    validate_waivers(&inputs.waivers)?;
    let ctx = Ctx::load(inputs);
    let mut waiver_notes = Vec::new();
    let mut items = Vec::with_capacity(ITEMS.len());
    for spec in ITEMS {
        let (mut state, mut detail) = if spec.model_only && !inputs.model_tier_changed {
            (
                ItemState::NotApplicable,
                "the model tier does not change in this release".to_owned(),
            )
        } else {
            let raw = match &spec.eval {
                Eval::Suite => eval_suite(&ctx, spec.id),
                Eval::Fn(f) => f(&ctx),
            };
            match raw {
                Raw::Pass(d) => (ItemState::Pass, d),
                Raw::Fail(d) => (ItemState::Fail, d),
                Raw::Unmeasured(d) => (ItemState::Unmeasured, d),
            }
        };
        let mut applied: Option<(NaiveDate, &Waiver)> = None;
        for w in inputs.waivers.iter().filter(|w| w.item == spec.id) {
            let Ok(until) = expiry(w) else { continue };
            if until < inputs.today {
                waiver_notes.push(format!(
                    "waiver for `{}` by {} expired on {until}",
                    w.item, w.owner
                ));
            } else if matches!(state, ItemState::Fail | ItemState::Unmeasured) {
                if applied.as_ref().is_none_or(|(d, _)| until > *d) {
                    applied = Some((until, w));
                }
            } else {
                waiver_notes.push(format!(
                    "waiver for `{}` by {} is unused: the item passes",
                    w.item, w.owner
                ));
            }
        }
        let waiver = applied.map(|(until, w)| {
            detail = format!(
                "waived by {} until {until}: {} (was {}: {detail})",
                w.owner,
                w.reason,
                state.as_str()
            );
            state = ItemState::Waived;
            w.clone()
        });
        items.push(ItemReport {
            id: spec.id.to_owned(),
            category: spec.category,
            title: spec.title.to_owned(),
            state,
            detail,
            evidence: spec.evidence.iter().map(|e| (*e).to_owned()).collect(),
            waiver,
        });
    }
    let mut counts = Counts::default();
    for item in &items {
        match item.state {
            ItemState::Pass => counts.pass += 1,
            ItemState::Fail => counts.fail += 1,
            ItemState::Unmeasured => counts.unmeasured += 1,
            ItemState::Waived => counts.waived += 1,
            ItemState::NotApplicable => counts.not_applicable += 1,
        }
    }
    let release_ready = items.iter().all(|i| i.state.clears());
    Ok(ReleaseReport {
        schema_version: SCHEMA_VERSION,
        evaluated_on: inputs.today.to_string(),
        release_ready,
        counts,
        items,
        waiver_notes,
    })
}

/// Item states keyed by id, for callers that only need the verdicts.
#[must_use]
pub fn states(report: &ReleaseReport) -> BTreeMap<&str, ItemState> {
    report.items.iter().map(|i| (i.id.as_str(), i.state)).collect()
}
