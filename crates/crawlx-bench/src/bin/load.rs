//! `load`: open-loop load generator for `crawlx serve` (`crawlx_bench::load`).
//!
//! ```text
//! load --base http://127.0.0.1:8080 --key cx_live_... [--rps 50] [--duration 20s]
//!      [--mix get=40,pages=30,coverage=20,create=5,events=5] [--runs 5] [--seed 7]
//!      [--max-p99-ms 150] [--fault SPEC] [--fault-seed N] [--allow-errors-during-fault]
//!      [--out bench/out/load-report.json]
//! ```
//!
//! Prints the per-route table; exit code 1 when any route's p99 exceeds `--max-p99-ms`
//! (150 ms for the metadata routes) or the error rate is non-zero. With `--fault` the
//! requests go through the `netfault` proxy while the schedule runs and the report splits
//! every route by in-fault and out-of-fault requests (`LoadReport::gate_failures`):
//! latency-only schedules keep both rules; schedules that break connections judge the p99
//! gate on out-of-fault requests, and with `--allow-errors-during-fault` allow failures only
//! inside the fault windows.

use crawlx_bench::load::{self, LoadConfig, Mix};
use crawlx_bench::netfault::FaultSchedule;
use crawlx_bench::soak::parse_duration;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: load --base URL --key KEY [options]\n\
  --base URL         API base, e.g. http://127.0.0.1:8080\n\
  --key KEY          bearer API key with crawls:read and crawls:write\n\
  --rps N            scheduled requests per second (default 50)\n\
  --duration D       scheduling window, e.g. 20s, 5m (default 20s)\n\
  --mix SPEC         route weights get=40,pages=30,coverage=20,create=5,events=5\n\
  --runs N           runs created up front for the read routes (default 5)\n\
  --seed N           seed of the route sequence (default 7)\n\
  --seed-url URL     seed URL of the created runs (default https://app.example.test/)\n\
  --max-in-flight N  requests in flight at once (default 256)\n\
  --max-p99-ms X     p99 ceiling per route (default 150)\n\
  --fault SPEC       run through the fault proxy: latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,\n\
                     refuse@25s..27s (offsets from the first request), or random:N for N faults\n\
                     generated over the load window; needs an http:// --base\n\
  --fault-seed N     seed of random:N (default: --seed)\n\
  --allow-errors-during-fault\n\
                     tolerate failures of requests that overlapped a blackhole, refuse or reset\n\
                     window; none may occur outside them (default: any failure fails the run)\n\
  --out FILE         JSON report path (default bench/out/load-report.json)";

struct Args {
    cfg: LoadConfig,
    max_p99_ms: f64,
    out: PathBuf,
    /// Fault schedule and the seed it was generated from.
    fault: Option<(FaultSchedule, Option<u64>)>,
    allow_errors_during_fault: bool,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut cfg = LoadConfig::default();
    let mut base = None;
    let mut key = None;
    let mut max_p99_ms = 150.0;
    let mut out = PathBuf::from("bench/out/load-report.json");
    let mut fault_spec = None;
    let mut fault_seed = None;
    let mut allow_errors_during_fault = false;
    let value = |it: &mut dyn Iterator<Item = String>, flag: &str| {
        it.next().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--base" => base = Some(value(&mut it, "--base")?.trim_end_matches('/').to_owned()),
            "--key" => key = Some(value(&mut it, "--key")?),
            "--rps" => {
                cfg.rps = value(&mut it, "--rps")?
                    .parse()
                    .map_err(|e| format!("--rps: {e}"))?
            }
            "--duration" => cfg.duration = parse_duration(&value(&mut it, "--duration")?)?,
            "--mix" => cfg.mix = Mix::parse(&value(&mut it, "--mix")?)?,
            "--runs" => {
                cfg.runs = value(&mut it, "--runs")?
                    .parse()
                    .map_err(|e| format!("--runs: {e}"))?
            }
            "--seed" => {
                cfg.seed = value(&mut it, "--seed")?
                    .parse()
                    .map_err(|e| format!("--seed: {e}"))?
            }
            "--seed-url" => cfg.seed_url = value(&mut it, "--seed-url")?,
            "--max-in-flight" => {
                cfg.max_in_flight = value(&mut it, "--max-in-flight")?
                    .parse()
                    .map_err(|e| format!("--max-in-flight: {e}"))?;
            }
            "--max-p99-ms" => {
                max_p99_ms = value(&mut it, "--max-p99-ms")?
                    .parse()
                    .map_err(|e| format!("--max-p99-ms: {e}"))?;
            }
            "--fault" => fault_spec = Some(value(&mut it, "--fault")?),
            "--fault-seed" => {
                fault_seed = Some(
                    value(&mut it, "--fault-seed")?
                        .parse()
                        .map_err(|e| format!("--fault-seed: {e}"))?,
                );
            }
            "--allow-errors-during-fault" => allow_errors_during_fault = true,
            "--out" => out = PathBuf::from(value(&mut it, "--out")?),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    cfg.base_url = base.ok_or_else(|| format!("--base is required\n{USAGE}"))?;
    cfg.api_key = key.ok_or_else(|| format!("--key is required\n{USAGE}"))?;
    let fault = match fault_spec {
        Some(spec) => Some(build_schedule(&spec, fault_seed, cfg.seed, cfg.duration)?),
        None if fault_seed.is_some() || allow_errors_during_fault => {
            return Err(format!(
                "--fault-seed and --allow-errors-during-fault need --fault\n{USAGE}"
            ))
        }
        None => None,
    };
    Ok(Args {
        cfg,
        max_p99_ms,
        out,
        fault,
        allow_errors_during_fault,
    })
}

/// `--fault SPEC`: an explicit schedule, or `random:N` for N faults generated from the seed
/// over the load window. Returns the schedule and the seed it was generated from.
fn build_schedule(
    spec: &str,
    fault_seed: Option<u64>,
    load_seed: u64,
    duration: std::time::Duration,
) -> Result<(FaultSchedule, Option<u64>), String> {
    if let Some(count) = spec.strip_prefix("random:") {
        let count: usize = count
            .parse()
            .map_err(|e| format!("--fault random:{count}: {e}"))?;
        let seed = fault_seed.unwrap_or(load_seed);
        let schedule = FaultSchedule::generate(seed, duration, count).map_err(|e| format!("--fault: {e}"))?;
        return Ok((schedule, Some(seed)));
    }
    if fault_seed.is_some() {
        return Err("--fault-seed only applies to --fault random:N".to_owned());
    }
    let schedule = FaultSchedule::parse(spec).map_err(|e| format!("--fault: {e}"))?;
    Ok((schedule, None))
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("load: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let run = match &args.fault {
        Some((schedule, seed)) => rt.block_on(load::run_faulted(&args.cfg, schedule, *seed)),
        None => rt.block_on(load::run(&args.cfg)),
    };
    let report = match run {
        Ok(r) => r,
        Err(e) => {
            eprintln!("load: {e}");
            return ExitCode::from(2);
        }
    };
    print!("{}", report.markdown());
    if let Some(parent) = args.out.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("load: create {}: {e}", parent.display());
            return ExitCode::from(2);
        }
    }
    match serde_json::to_vec_pretty(&report) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&args.out, json) {
                eprintln!("load: write {}: {e}", args.out.display());
                return ExitCode::from(2);
            }
        }
        Err(e) => {
            eprintln!("load: serialize: {e}");
            return ExitCode::from(2);
        }
    }
    let failures = report.gate_failures(args.max_p99_ms, args.allow_errors_during_fault);
    for failure in &failures {
        eprintln!("load: {failure}");
    }
    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
