//! `soak`: the soak harness (`crawlx_bench::soak`).
//!
//! ```text
//! soak [--duration 24h] [--workers 4] [--fixtures d1,g01,...] [--fake]
//!      [--database-url URL | env CRAWLX_TEST_DATABASE_URL] [--memory]
//!      [--sample-interval 30s] [--seed N] [--interactions 40] [--cycle-seconds 120]
//!      [--max-slope-mib-per-hour 32] [--fault-every 10m] [--keep-schema] [--out bench/out]
//! ```
//!
//! Exit code 0 for `pass` or `inconclusive` (short runs), 1 for `fail`, 2 for a setup error.

use crawlx_bench::soak::{self, parse_duration, SoakBackend, SoakConfig, Verdict};
use crawlx_browser::launch::find_executable;
use std::path::PathBuf;
use std::process::ExitCode;

// Measure the same allocator as the production `crawlx` executable.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "usage: soak [options]\n\
  --duration D                wall-clock budget, e.g. 24h, 10m, 30s (default 24h)\n\
  --workers N                 parallel worker loops (default 4)\n\
  --fixtures IDS              comma-separated gym fixture ids (default: the D1 set)\n\
  --fake                      FakeBackend scripted from the manifests instead of Chromium\n\
  --database-url URL          postgres:, mariadb: or sqlite: URL (default: $CRAWLX_TEST_DATABASE_URL)\n\
  --memory                    in-memory store per cycle even when the env var is set\n\
  --sample-interval D         RSS/pool sampling period (default 30s)\n\
  --seed N                    base crawl seed (default 20261020)\n\
  --interactions N            interaction budget per cycle (default 40)\n\
  --cycle-seconds N           wall-clock limit per cycle (default 120)\n\
  --max-slope-mib-per-hour X  leak-slope ceiling (default 32)\n\
  --min-slope-window D        shortest fitted window for a leak verdict (default 8m)\n\
  --fault-every D             one seeded network fault per period through the netfault proxy (network databases only: postgres, mariadb)\n\
  --keep-schema               keep the isolated schema (PostgreSQL) after the run\n\
  --out DIR                   report directory (default bench/out)";

struct Args {
    cfg: SoakConfig,
    out: PathBuf,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut cfg = SoakConfig {
        database_url: std::env::var("CRAWLX_TEST_DATABASE_URL").ok(),
        ..SoakConfig::default()
    };
    let mut out = PathBuf::from("bench/out");
    let mut memory = false;
    let value = |it: &mut dyn Iterator<Item = String>, flag: &str| {
        it.next().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--duration" => cfg.duration = parse_duration(&value(&mut it, "--duration")?)?,
            "--workers" => {
                cfg.workers = value(&mut it, "--workers")?
                    .parse()
                    .map_err(|e| format!("--workers: {e}"))?
            }
            "--fixtures" => {
                cfg.fixtures = value(&mut it, "--fixtures")?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            "--fake" => cfg.backend = SoakBackend::Fake,
            "--database-url" => cfg.database_url = Some(value(&mut it, "--database-url")?),
            "--memory" => memory = true,
            "--sample-interval" => {
                cfg.sample_interval = parse_duration(&value(&mut it, "--sample-interval")?)?
            }
            "--seed" => {
                cfg.seed = value(&mut it, "--seed")?
                    .parse()
                    .map_err(|e| format!("--seed: {e}"))?
            }
            "--interactions" => {
                cfg.interactions = value(&mut it, "--interactions")?
                    .parse()
                    .map_err(|e| format!("--interactions: {e}"))?;
            }
            "--cycle-seconds" => {
                cfg.cycle_seconds = value(&mut it, "--cycle-seconds")?
                    .parse()
                    .map_err(|e| format!("--cycle-seconds: {e}"))?;
            }
            "--max-slope-mib-per-hour" => {
                let mib: f64 = value(&mut it, "--max-slope-mib-per-hour")?
                    .parse()
                    .map_err(|e| format!("--max-slope-mib-per-hour: {e}"))?;
                cfg.max_slope_bytes_per_hour = mib * 1024.0 * 1024.0;
            }
            "--fault-every" => cfg.fault_every = Some(parse_duration(&value(&mut it, "--fault-every")?)?),
            "--min-slope-window" => {
                cfg.min_slope_window = parse_duration(&value(&mut it, "--min-slope-window")?)?
            }
            "--keep-schema" => cfg.keep_schema = true,
            "--out" => out = PathBuf::from(value(&mut it, "--out")?),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if memory {
        cfg.database_url = None;
    }
    if cfg.fault_every.is_some() && cfg.database_url.is_none() {
        return Err("--fault-every needs a postgres or mariadb database".to_owned());
    }
    Ok(Args { cfg, out })
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    if args.cfg.backend == SoakBackend::Chromium && find_executable().is_none() {
        eprintln!("soak: no Chromium executable found (set CRAWLX_CHROMIUM_PATH or pass --fake)");
        return ExitCode::from(2);
    }
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("CRAWLX_LOG").unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("info,crawlx_worker=warn,crawlx_browser=warn")
            }),
        )
        .with_writer(std::io::stderr)
        .finish();
    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("soak: tracing: {e}");
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("soak: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let report = match rt.block_on(soak::run(args.cfg, &args.out)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("soak: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                eprintln!("  caused by: {s}");
                src = s.source();
            }
            return ExitCode::from(2);
        }
    };
    print!("{}", report.markdown());
    eprintln!(
        "soak: wrote {} and soak-report.md",
        args.out.join("soak-report.json").display()
    );
    match report.verdict {
        Verdict::Pass | Verdict::Inconclusive(_) => ExitCode::SUCCESS,
        Verdict::Fail(_) => ExitCode::from(1),
    }
}
