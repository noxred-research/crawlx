//! Capture completed G1 chaos suites as structured evidence, never a caller-supplied boolean.

use clap::Parser;
use crawlx_bench::gates::ChaosEvidence;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
struct Args {
    /// Structured output retained even when a completed suite fails.
    #[arg(long)]
    out: PathBuf,
}

fn run(args: Args) -> Result<bool, String> {
    let report = ChaosEvidence::run().map_err(|error| error.to_string())?;
    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    std::fs::write(&args.out, bytes).map_err(|error| error.to_string())?;
    for suite in &report.suites {
        eprintln!(
            "{}: exit {:?}\n{}\n{}",
            suite.suite, suite.exit_code, suite.stdout, suite.stderr
        );
    }
    Ok(report.passed())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("chaos-report: {error}");
            ExitCode::from(2)
        }
    }
}
