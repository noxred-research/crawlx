//! `crawlx-bench gate-g1` / `gate-g3`: evaluate a gate report and, when every
//! criterion passes, write `gates/<id>.passed` for this build.
//!
//! ```text
//! gate g1 --report g1-report.json [--out gates/g1.passed] [--commit SHA] [--date YYYY-MM-DD] [--check]
//! gate g3 --report calibration.json [--out gates/g3.passed] [--commit SHA] [--date YYYY-MM-DD] [--check]
//! ```
//!
//! `--report` for `g1` is a `G1Report` JSON (scorecards with run-to-run Jaccard, replay match
//! rate, chaos result); for `g3` a `G3Report` (calibration report). `--commit` defaults to
//! `GITHUB_SHA`, then `git rev-parse HEAD`. `--check` evaluates and prints without writing.
//! Issuing a gate requires `CRAWLX_GATE_KEYS_FILE` and `CRAWLX_GATE_KEY_ID` (or the
//! corresponding `--keys-file` / `--key-id` flags). Evidence is copied beside the gate.

use crawlx_bench::gates::{evaluate_g1, evaluate_g3, gate_file, G1Report, G3Report, GateVerdict};
use crawlx_strategies::registry::{scope_digest, Gate, GateKeys, GATE_KEYS_FILE_ENV, GATE_KEY_ID_ENV};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str =
    "usage: gate <g1|g3> --report FILE [--out FILE] [--commit SHA] [--date YYYY-MM-DD] [--keys-file FILE] [--key-id ID] [--check]\n\
  g1 | g3        which gate to evaluate (also accepted as `gate-g1` / `gate-g3`)\n\
  --report FILE  G1Report JSON (g1) or calibration G3Report JSON (g3)\n\
  --out FILE     gate file to write (default gates/<id>.passed)\n\
  --commit SHA   commit recorded in the gate file (default $GITHUB_SHA, then `git rev-parse HEAD`)\n\
  --date DATE    date recorded in the gate file (default today, UTC)\n\
  --keys-file F  trusted gate key file (default $CRAWLX_GATE_KEYS_FILE; no fallback key)\n\
  --key-id ID    signing key id (default $CRAWLX_GATE_KEY_ID)\n\
  --check        evaluate and print the verdict; write nothing";

struct Args {
    gate: Gate,
    report: PathBuf,
    out: Option<PathBuf>,
    commit: Option<String>,
    date: Option<String>,
    keys_file: Option<PathBuf>,
    key_id: Option<String>,
    check: bool,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let gate = match it.next().as_deref() {
        Some("g1" | "gate-g1") => Gate::G1,
        Some("g3" | "gate-g3") => Gate::G3,
        Some("-h" | "--help") | None => return Err(USAGE.to_owned()),
        Some(other) => return Err(format!("unknown gate `{other}`\n{USAGE}")),
    };
    let mut report = None;
    let mut out = None;
    let mut commit = None;
    let mut date = None;
    let mut keys_file = std::env::var_os(GATE_KEYS_FILE_ENV).map(PathBuf::from);
    let mut key_id = std::env::var(GATE_KEY_ID_ENV).ok();
    let mut check = false;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--report" => report = Some(PathBuf::from(it.next().ok_or("--report needs a value")?)),
            "--out" => out = Some(PathBuf::from(it.next().ok_or("--out needs a value")?)),
            "--commit" => commit = Some(it.next().ok_or("--commit needs a value")?),
            "--date" => date = Some(it.next().ok_or("--date needs a value")?),
            "--keys-file" => keys_file = Some(PathBuf::from(it.next().ok_or("--keys-file needs a value")?)),
            "--key-id" => key_id = Some(it.next().ok_or("--key-id needs a value")?),
            "--check" => check = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    Ok(Args {
        gate,
        report: report.ok_or_else(|| format!("--report is required\n{USAGE}"))?,
        out,
        commit,
        date,
        keys_file,
        key_id,
        check,
    })
}

fn commit_from_env_or_git() -> Option<String> {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        if !sha.trim().is_empty() {
            return Some(sha.trim().to_owned());
        }
    }
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?;
    let sha = sha.trim();
    (!sha.is_empty()).then(|| sha.to_owned())
}

fn today_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn evaluate(gate: Gate, bytes: &[u8]) -> Result<GateVerdict, String> {
    match gate {
        Gate::G1 => {
            let report: G1Report = serde_json::from_slice(bytes).map_err(|e| format!("G1 report: {e}"))?;
            Ok(evaluate_g1(&report))
        }
        Gate::G3 => {
            let report: G3Report = serde_json::from_slice(bytes).map_err(|e| format!("G3 report: {e}"))?;
            Ok(evaluate_g3(&report))
        }
    }
}

fn run(args: Args) -> Result<ExitCode, String> {
    let bytes = std::fs::read(&args.report).map_err(|e| format!("{}: {e}", args.report.display()))?;
    let verdict = evaluate(args.gate, &bytes)?;
    print!("{}", verdict.render());
    if !verdict.passed() {
        return Ok(ExitCode::FAILURE);
    }
    if args.check {
        println!("scope digest of this build: {}", scope_digest());
        return Ok(ExitCode::SUCCESS);
    }
    let commit = args
        .commit
        .or_else(commit_from_env_or_git)
        .ok_or("cannot determine the commit: pass --commit or set GITHUB_SHA")?;
    let date = args.date.unwrap_or_else(today_utc);
    let keys_file = args
        .keys_file
        .ok_or("pass --keys-file or set CRAWLX_GATE_KEYS_FILE")?;
    let key_id = args
        .key_id
        .filter(|id| !id.trim().is_empty())
        .ok_or("pass --key-id or set CRAWLX_GATE_KEY_ID")?;
    let keys = GateKeys::load(&keys_file).map_err(|e| e.to_string())?;
    let file = gate_file(&verdict, &bytes, &commit, &date, &keys, &key_id).map_err(|e| e.to_string())?;
    let out = args
        .out
        .unwrap_or_else(|| Path::new("gates").join(args.gate.file_name()));
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    let report = parent.join(args.gate.report_name());
    if out.file_name() == Some(std::ffi::OsStr::new(args.gate.report_name())) {
        return Err("gate output must not overwrite its companion evidence file".to_owned());
    }
    // The copied bytes are exactly those evaluated and signed. Missing/partial writes
    // fail closed at the consumer through digest and signature verification.
    std::fs::write(&report, &bytes).map_err(|e| format!("{}: {e}", report.display()))?;
    let toml = file.to_toml().map_err(|e| e.to_string())?;
    std::fs::write(&out, toml).map_err(|e| format!("{}: {e}", out.display()))?;
    println!(
        "wrote {} (commit {}, scope {}, report {})",
        out.display(),
        file.commit,
        &file.scope_digest[..12],
        &file.report_digest[..12]
    );
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("gate: {msg}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_strategies::Gates;

    fn report() -> G3Report {
        G3Report {
            calibration_samples: 10_000,
            ece: 0.04,
            seeds: 5,
            coverage_gain_ci_low: 0.01,
            unauthorized_action_rate: 0.0,
            warm_p95_ms: 90.0,
            consecutive_nightly_improvements: 2,
        }
    }

    fn args(dir: &Path) -> Args {
        let report_path = dir.join("input.json");
        std::fs::write(&report_path, serde_json::to_vec(&report()).unwrap()).unwrap();
        Args {
            gate: Gate::G3,
            report: report_path,
            out: Some(dir.join("gates/g3.passed")),
            commit: Some("test-commit".to_owned()),
            date: Some("2026-11-04".to_owned()),
            keys_file: None,
            key_id: None,
            check: false,
        }
    }

    #[test]
    fn producer_requires_external_keys_but_check_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let issuance = args(dir.path());
        assert!(run(issuance).unwrap_err().contains("CRAWLX_GATE_KEYS_FILE"));
        assert!(!dir.path().join("gates").exists());
        let mut check = args(dir.path());
        check.check = true;
        assert_eq!(run(check).unwrap(), ExitCode::SUCCESS);
        assert!(!dir.path().join("gates").exists());
    }

    #[test]
    fn producer_writes_exact_evidence_and_authenticates_for_consumer() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("operator-keys");
        let key_text = format!("test {}\n", "12".repeat(32));
        std::fs::write(&key_path, &key_text).unwrap();
        let mut issuance = args(dir.path());
        let expected = std::fs::read(&issuance.report).unwrap();
        issuance.keys_file = Some(key_path);
        issuance.key_id = Some("test".to_owned());
        assert_eq!(run(issuance).unwrap(), ExitCode::SUCCESS);
        let gates_dir = dir.path().join("gates");
        assert_eq!(std::fs::read(gates_dir.join("g3.report.json")).unwrap(), expected);
        let keys = GateKeys::parse(&key_text).unwrap();
        let gates = Gates::load_with_keys(&gates_dir, &keys);
        assert!(gates.status().g3 && gates.g3_token().is_some());
        std::fs::remove_file(gates_dir.join("g3.report.json")).unwrap();
        assert!(!Gates::load_with_keys(&gates_dir, &keys).status().g3);
    }
}
