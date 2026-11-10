//! `flake-report`: record test runs, publish the flake rate, quarantine repeat flakes.
//!
//! ```text
//! flake-report record --junit FILE... --history FILE [--date D] --suite NAME
//! flake-report report --history FILE [--date D] --out bench/out/flake-report.json
//!                     [--markdown FILE] [--quarantine FILE] [--suite NAME]... [--release-gate]
//! flake-report quarantine --history FILE [--date D] --file ci/quarantine.toml
//! flake-report filter --file ci/quarantine.toml [--only]
//! flake-report check --file ci/quarantine.toml [--date D]
//! ```
//!
//! `--date` is `YYYY-MM-DD` and defaults to today (UTC). `record` reads the junit files a
//! `cargo nextest run --profile ci` wrote and appends one run to the history. `report` writes
//! `{window_days, runs, flaky_runs}` for the PR suites (every suite but `nightly`, or the
//! `--suite` names) and, with `--markdown`, one issue body per flaky test; with
//! `--release-gate` it exits 1 unless the flake rate is below 1%. `quarantine` adds the tests
//! with 3 flake events in 14 days and keeps the existing entries. `filter` prints the nextest
//! filterset that excludes the quarantined tests (the PR profile) or, with `--only`, selects only
//! them (the nightly run). `check` exits 1 for a test quarantined for more than 14 days. Exit
//! status 2 is a usage or input error. See `docs/ops/flaky-tests.md`.

use chrono::NaiveDate;
use clap::{Parser, Subcommand};
use crawlx_bench::flake::{
    report_markdown, FlakeError, History, JunitReport, Outcome, Quarantine, QUARANTINE_DEADLINE_DAYS,
    RELEASE_MAX_FLAKE_PERCENT,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "flake-report",
    about = "Flake history, quarantine and flake-rate tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Append the junit results of one suite run to the history.
    Record {
        /// Junit files written by `cargo nextest run --profile ci`.
        #[arg(long, required = true, num_args = 1..)]
        junit: Vec<PathBuf>,
        /// The history file; created when absent.
        #[arg(long)]
        history: PathBuf,
        /// Day of the run (default: today, UTC).
        #[arg(long)]
        date: Option<NaiveDate>,
        /// Suite name; `nightly` marks the quarantine run.
        #[arg(long)]
        suite: String,
    },
    /// Write the flake rate and, optionally, the issue bodies.
    Report {
        /// The history file.
        #[arg(long)]
        history: PathBuf,
        /// Day the window ends on (default: today, UTC).
        #[arg(long)]
        date: Option<NaiveDate>,
        /// Output JSON: `window_days`, `runs`, `flaky_runs`.
        #[arg(long)]
        out: PathBuf,
        /// Markdown file with one issue body per flaky test.
        #[arg(long)]
        markdown: Option<PathBuf>,
        /// The quarantine file the markdown refers to.
        #[arg(long, default_value = "ci/quarantine.toml")]
        quarantine: PathBuf,
        /// Count only these suites (default: every suite except `nightly`).
        #[arg(long)]
        suite: Vec<String>,
        /// Exit 1 unless the flake rate is below the release limit.
        #[arg(long)]
        release_gate: bool,
    },
    /// Quarantine the tests with 3 flake events in 14 days; existing entries stay.
    Quarantine {
        /// The history file.
        #[arg(long)]
        history: PathBuf,
        /// Day the window ends on and the new entries are dated (default: today, UTC).
        #[arg(long)]
        date: Option<NaiveDate>,
        /// The quarantine file; created when absent.
        #[arg(long)]
        file: PathBuf,
    },
    /// Print the nextest filterset for the quarantine file.
    Filter {
        /// The quarantine file.
        #[arg(long)]
        file: PathBuf,
        /// Select only the quarantined tests instead of excluding them.
        #[arg(long)]
        only: bool,
    },
    /// Exit 1 when a test is quarantined for more than 14 days.
    Check {
        /// The quarantine file.
        #[arg(long)]
        file: PathBuf,
        /// Today (default: today, UTC).
        #[arg(long)]
        date: Option<NaiveDate>,
    },
}

fn today(date: Option<NaiveDate>) -> NaiveDate {
    date.unwrap_or_else(|| chrono::Utc::now().date_naive())
}

fn record(junit: &[PathBuf], history: &Path, date: NaiveDate, suite: &str) -> Result<bool, FlakeError> {
    let mut report = JunitReport::default();
    for file in junit {
        let text = std::fs::read_to_string(file).map_err(|source| FlakeError::Io {
            path: file.clone(),
            source,
        })?;
        report.merge(JunitReport::parse(&text)?);
    }
    let mut store = History::load(history)?;
    store.record(date, suite, &report);
    store.save(history)?;
    let flaky = report.with_outcome(Outcome::Flaky);
    let failed = report.with_outcome(Outcome::Failed);
    eprintln!(
        "flake-report: recorded {suite} {date}: {} executions, {} flaky, {} failed",
        report.executions(),
        flaky.len(),
        failed.len()
    );
    for id in flaky {
        eprintln!("flake-report: FLAKY {id}");
    }
    Ok(true)
}

fn report(
    history: &Path,
    date: NaiveDate,
    out: &Path,
    markdown: Option<&Path>,
    quarantine: &Path,
    suites: &[String],
    release_gate: bool,
) -> Result<bool, FlakeError> {
    let store = History::load(history)?;
    let summary = if suites.is_empty() {
        store.pr_summary(date)
    } else {
        store.summary(date, |suite| suites.iter().any(|s| s == suite))
    };
    summary.save(out)?;
    eprintln!(
        "flake-report: {} flaky of {} executions in {} days",
        summary.flaky_runs, summary.runs, summary.window_days
    );
    if let Some(path) = markdown {
        let text = report_markdown(&store, &Quarantine::load(quarantine)?, date);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|source| FlakeError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(path, text).map_err(|source| FlakeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    if release_gate && !summary.meets_release_gate() {
        eprintln!(
            "flake-report: release gate needs a flake rate below {RELEASE_MAX_FLAKE_PERCENT}% over {} days with recorded executions",
            summary.window_days
        );
        return Ok(false);
    }
    Ok(true)
}

fn quarantine(history: &Path, date: NaiveDate, file: &Path) -> Result<bool, FlakeError> {
    let store = History::load(history)?;
    let mut list = Quarantine::load(file)?;
    let added = list.add_candidates(&store.quarantine_candidates(date), date);
    list.save(file)?;
    for id in &added {
        eprintln!("flake-report: quarantined {id}");
    }
    eprintln!(
        "flake-report: {} added, {} quarantined",
        added.len(),
        list.test.len()
    );
    Ok(true)
}

fn check(file: &Path, date: NaiveDate) -> Result<bool, FlakeError> {
    let list = Quarantine::load(file)?;
    let expired = list.expired(date);
    for entry in &expired {
        eprintln!(
            "flake-report: {} has been quarantined since {} (more than {QUARANTINE_DEADLINE_DAYS} days): fix or delete it",
            entry.id, entry.since
        );
    }
    Ok(expired.is_empty())
}

fn run(cli: Cli) -> Result<bool, FlakeError> {
    match cli.command {
        Command::Record {
            junit,
            history,
            date,
            suite,
        } => record(&junit, &history, today(date), &suite),
        Command::Report {
            history,
            date,
            out,
            markdown,
            quarantine,
            suite,
            release_gate,
        } => report(
            &history,
            today(date),
            &out,
            markdown.as_deref(),
            &quarantine,
            &suite,
            release_gate,
        ),
        Command::Quarantine { history, date, file } => quarantine(&history, today(date), &file),
        Command::Filter { file, only } => {
            let list = Quarantine::load(&file)?;
            println!(
                "{}",
                if only {
                    list.filterset_only()
                } else {
                    list.filterset_exclude()
                }
            );
            Ok(true)
        }
        Command::Check { file, date } => check(&file, today(date)),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            // the error plus every source, on one line
            let mut line = error.to_string();
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                line.push_str(": ");
                line.push_str(&cause.to_string());
                source = cause.source();
            }
            eprintln!("flake-report: {line}");
            ExitCode::from(2)
        }
    }
}
