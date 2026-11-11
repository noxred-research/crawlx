//! `release-gate`: compute the release checklist from evidence files, or record a suite result
//! into the evidence directory (`crawlx_bench::release_gate`, `docs/ops/release-gates.md`).
//!
//! ```text
//! release-gate [check] [--evidence DIR] [--repo DIR] [--out FILE] [--markdown FILE]
//!              [--waivers FILE] [--today YYYY-MM-DD] [--model-tier-changed]
//! release-gate record --id SUITE [--evidence DIR] [--tool] -- COMMAND [ARGS...]
//! ```
//!
//! `check` prints the markdown checklist and exits 0 only when every applicable item passes or
//! is waived, 1 when the release is blocked (a `fail` or `unmeasured` item), 2 on a usage error
//! or a malformed waiver. `record` runs the command, stores its exit status and libtest summary
//! as `suites/SUITE.json` and exits with 0 whenever the result was recorded: the verdict is
//! computed later by `check`.

use chrono::NaiveDate;
use crawlx_bench::release_gate::{evaluate, parse_waivers, record_suite, GateInputs, SUITE_IDS};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: release-gate [check] [options]\n\
       release-gate record --id SUITE [--evidence DIR] [--tool] -- COMMAND [ARGS...]\n\
check options:\n\
  --evidence DIR        evidence directory (default bench/out)\n\
  --repo DIR            repository root (default .)\n\
  --out FILE            JSON report path (default DIR/release-checklist.json)\n\
  --markdown FILE       markdown checklist path (default: print only)\n\
  --waivers FILE        waivers JSON (default bench/baselines/release-waivers.json when present)\n\
  --today YYYY-MM-DD    date waivers and the restore drill are judged against (default: today, UTC)\n\
  --model-tier-changed  the model tier changes in this release: the model item applies\n\
record options:\n\
  --id SUITE            suite id; one of the ids listed in docs/ops/release-gates.md\n\
  --tool                the command is not a libtest run (cargo deny, ci/bench-gate.sh): exit status only";

struct CheckArgs {
    evidence: PathBuf,
    repo: PathBuf,
    out: Option<PathBuf>,
    markdown: Option<PathBuf>,
    waivers: Option<PathBuf>,
    today: Option<NaiveDate>,
    model_tier_changed: bool,
}

struct RecordArgs {
    evidence: PathBuf,
    id: String,
    tool: bool,
    command: Vec<String>,
}

enum Cmd {
    Check(CheckArgs),
    Record(RecordArgs),
}

fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn parse(args: Vec<String>) -> Result<Cmd, String> {
    let mut it = args.into_iter().peekable();
    let record = match it.peek().map(String::as_str) {
        Some("record") => {
            it.next();
            true
        }
        Some("check") => {
            it.next();
            false
        }
        _ => false,
    };
    let mut evidence = PathBuf::from("bench/out");
    if record {
        let mut id = None;
        let mut tool = false;
        let mut command = Vec::new();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--evidence" => evidence = PathBuf::from(value(&mut it, "--evidence")?),
                "--id" => id = Some(value(&mut it, "--id")?),
                "--tool" => tool = true,
                "--" => {
                    command = it.by_ref().collect();
                }
                "-h" | "--help" => return Err(USAGE.to_owned()),
                other => return Err(format!("unknown argument {other}\n{USAGE}")),
            }
        }
        let id = id.ok_or_else(|| format!("--id is required (known: {})\n{USAGE}", SUITE_IDS.join(", ")))?;
        if command.is_empty() {
            return Err(format!("record needs `-- COMMAND`\n{USAGE}"));
        }
        return Ok(Cmd::Record(RecordArgs {
            evidence,
            id,
            tool,
            command,
        }));
    }
    let mut args = CheckArgs {
        evidence,
        repo: PathBuf::from("."),
        out: None,
        markdown: None,
        waivers: None,
        today: None,
        model_tier_changed: false,
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--evidence" => args.evidence = PathBuf::from(value(&mut it, "--evidence")?),
            "--repo" => args.repo = PathBuf::from(value(&mut it, "--repo")?),
            "--out" => args.out = Some(PathBuf::from(value(&mut it, "--out")?)),
            "--markdown" => args.markdown = Some(PathBuf::from(value(&mut it, "--markdown")?)),
            "--waivers" => args.waivers = Some(PathBuf::from(value(&mut it, "--waivers")?)),
            "--today" => {
                let text = value(&mut it, "--today")?;
                args.today = Some(
                    NaiveDate::parse_from_str(&text, "%Y-%m-%d")
                        .map_err(|e| format!("--today `{text}`: {e}"))?,
                );
            }
            "--model-tier-changed" => args.model_tier_changed = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    Ok(Cmd::Check(args))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

/// `Ok(true)` when the release is ready.
fn check(args: CheckArgs) -> Result<bool, String> {
    let today = args.today.unwrap_or_else(|| chrono::Utc::now().date_naive());
    let mut inputs = GateInputs::new(&args.evidence, &args.repo, today);
    inputs.model_tier_changed = args.model_tier_changed;
    let default_waivers = args.repo.join("bench/baselines/release-waivers.json");
    let waivers_path = args
        .waivers
        .or_else(|| default_waivers.exists().then_some(default_waivers));
    if let Some(path) = &waivers_path {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        inputs.waivers = parse_waivers(&text).map_err(|e| format!("{}: {}", path.display(), e.chain()))?;
    }
    let report = evaluate(&inputs).map_err(|e| e.chain())?;
    let markdown = report.markdown();
    print!("{markdown}");
    let json_path = args
        .out
        .unwrap_or_else(|| args.evidence.join("release-checklist.json"));
    let json = serde_json::to_vec_pretty(&report).map_err(|e| format!("serialize: {e}"))?;
    write_file(&json_path, &json)?;
    if let Some(path) = &args.markdown {
        write_file(path, markdown.as_bytes())?;
    }
    Ok(report.ready())
}

fn record(args: &RecordArgs) -> Result<(), String> {
    let result = record_suite(&args.evidence, &args.id, &args.command, !args.tool).map_err(|e| e.chain())?;
    eprintln!(
        "release-gate: recorded suite `{}`: exit {:?}, {} passed, {} failed, {} ignored, {} skipped",
        result.id, result.exit_code, result.passed, result.failed, result.ignored, result.skipped
    );
    Ok(())
}

fn main() -> ExitCode {
    match parse(std::env::args().skip(1).collect()) {
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Ok(Cmd::Check(args)) => match check(args) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => {
                eprintln!("release-gate: the release is blocked");
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("release-gate: {e}");
                ExitCode::from(2)
            }
        },
        Ok(Cmd::Record(args)) => match record(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("release-gate: {e}");
                ExitCode::from(2)
            }
        },
    }
}
