//! `load`: open-loop load generator for `crawlx serve` (`crawlx_bench::load`).
//!
//! ```text
//! load --base http://127.0.0.1:8080 --key cx_live_... [--rps 50] [--duration 20s]
//!      [--mix get=40,pages=30,coverage=20,create=5,events=5] [--runs 5] [--seed 7]
//!      [--max-p99-ms 150] [--out bench/out/load-report.json]
//! ```
//!
//! Prints the per-route table; exit code 1 when any route's p99 exceeds `--max-p99-ms`
//! (150 ms for the metadata routes) or the error rate is non-zero.

use crawlx_bench::load::{self, LoadConfig, Mix};
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
  --out FILE         JSON report path (default bench/out/load-report.json)";

struct Args {
    cfg: LoadConfig,
    max_p99_ms: f64,
    out: PathBuf,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut cfg = LoadConfig::default();
    let mut base = None;
    let mut key = None;
    let mut max_p99_ms = 150.0;
    let mut out = PathBuf::from("bench/out/load-report.json");
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
            "--out" => out = PathBuf::from(value(&mut it, "--out")?),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    cfg.base_url = base.ok_or_else(|| format!("--base is required\n{USAGE}"))?;
    cfg.api_key = key.ok_or_else(|| format!("--key is required\n{USAGE}"))?;
    Ok(Args { cfg, max_p99_ms, out })
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
    let report = match rt.block_on(load::run(&args.cfg)) {
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
    let mut failed = false;
    for (route, r) in &report.routes {
        if r.p99_ms > args.max_p99_ms {
            eprintln!(
                "load: {route}: p99 {:.1} ms above {:.1} ms",
                r.p99_ms, args.max_p99_ms
            );
            failed = true;
        }
        if r.error_rate() > 0.0 {
            eprintln!("load: {route}: error rate {:.4}", r.error_rate());
            failed = true;
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
