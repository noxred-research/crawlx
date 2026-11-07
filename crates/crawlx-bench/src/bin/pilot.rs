//! `pilot`: the seed-count pilot.
//!
//! Runs the A8 baseline on the pilot fixture set for every seed of the committed `pilot`
//! suite (`bench/seeds.toml`), computes `pilot_variance` of trusted action-context coverage
//! per fixture and reports the seed count the nightly and release suites need for a
//! confidence-interval half-width of `--half-width` (planning default 0.02) at `--level`
//! (0.95). The JSON report carries every per-seed sample so the analysis can be redone
//! without re-running the matrix.
//!
//! ```text
//! pilot --out FILE [--fixtures IDS] [--seeds N] [--interactions N] [--duration SECS]
//!       [--half-width H] [--level L] [--variant ID]
//! ```

use crawlx_bench::ablation::{self, AblationRunner, AblationVariant};
use crawlx_bench::error::BenchError;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::stats::{pilot_variance, PilotAnalysis, SeedSets};
use crawlx_bench::worker_exec::WorkerExecutor;
use crawlx_browser::launch::find_executable;
use crawlx_core::config::SafetyProfile;
use serde::Serialize;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: pilot --out FILE [--fixtures IDS] [--seeds N] [--interactions N] [--duration SECS] [--half-width H] [--level L] [--variant ID]\n\
--out FILE          where to write the pilot report JSON (a .md sibling is written too)\n\
--fixtures IDS      comma-separated gym fixture ids (default: g01,g02,g06,g20,g26, one per metric family)\n\
--seeds N           use the first N seeds of the committed `pilot` suite (default: all 30)\n\
--interactions N    interaction budget per run (default 60)\n\
--duration SECS     wall-clock limit per run (default 180; the budget, not the clock, must end runs)\n\
--half-width H      target half-width on trusted coverage (default 0.02)\n\
--level L           confidence level (default 0.95)\n\
--variant ID        ablation variant to run (default A8, the production baseline)";

/// Fixture set of the pilot: one fixture per metric family.
const DEFAULT_FIXTURES: [&str; 5] = ["g01", "g02", "g06", "g20", "g26"];

struct Args {
    out: PathBuf,
    fixtures: Vec<String>,
    seeds: Option<usize>,
    interactions: u32,
    duration: u32,
    half_width: f64,
    level: f64,
    variant: String,
}

/// Per-fixture pilot result.
#[derive(Serialize)]
struct FixturePilot {
    fixture: String,
    seeds: Vec<u64>,
    /// Trusted action-context coverage per seed, in `seeds` order.
    trusted_coverage: Vec<f64>,
    /// Interaction count at which 80 % coverage was first reached, per seed (`null` if never).
    t80: Vec<Option<u64>>,
    coverage: PilotAnalysis,
    /// Variance analysis of `T80` over the seeds that reached it (`None` below two).
    t80_analysis: Option<PilotAnalysis>,
}

/// The pilot report (`bench/out/pilot-report.json`).
#[derive(Serialize)]
struct PilotReport {
    variant: String,
    interactions: u32,
    duration_seconds: u32,
    target_half_width: f64,
    level: f64,
    fixtures: Vec<FixturePilot>,
    /// Largest `seeds_needed` over the fixtures: the count the nightly/release suites need.
    seeds_needed: usize,
}

impl PilotReport {
    fn render_markdown(&self) -> String {
        let mut s = format!(
            "# Pilot variance ({}, {} interactions, {} s, half-width {}, level {})\n\n| Fixture | Seeds | Mean coverage | Variance | Pilot half-width | Seeds needed | T80 mean |\n|---|---:|---:|---:|---:|---:|---:|\n",
            self.variant, self.interactions, self.duration_seconds, self.target_half_width, self.level
        );
        for f in &self.fixtures {
            let t80 = f
                .t80_analysis
                .as_ref()
                .map_or("n/a".to_owned(), |a| format!("{:.1}", a.mean));
            s.push_str(&format!(
                "| {} | {} | {:.4} | {:.6} | {:.4} | {} | {} |\n",
                f.fixture,
                f.seeds.len(),
                f.coverage.mean,
                f.coverage.variance,
                f.coverage.pilot_half_width,
                f.coverage.seeds_needed,
                t80
            ));
        }
        s.push_str(&format!(
            "\nSeeds needed for every fixture at once: **{}**.\n",
            self.seeds_needed
        ));
        s
    }
}

fn value<I: Iterator<Item = String>>(it: &mut I, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
}

fn parse<I: Iterator<Item = String>>(mut it: I) -> Result<Args, String> {
    let mut out = None;
    let mut fixtures: Vec<String> = DEFAULT_FIXTURES.iter().map(|s| (*s).to_owned()).collect();
    let mut seeds = None;
    let mut interactions = 60;
    let mut duration = 180;
    let mut half_width = 0.02;
    let mut level = 0.95;
    let mut variant = "A8".to_owned();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--out" => out = Some(PathBuf::from(value(&mut it, "--out")?)),
            "--fixtures" => {
                fixtures = value(&mut it, "--fixtures")?
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--seeds" => {
                seeds = Some(
                    value(&mut it, "--seeds")?
                        .parse()
                        .map_err(|e| format!("--seeds: {e}"))?,
                );
            }
            "--interactions" => {
                interactions = value(&mut it, "--interactions")?
                    .parse()
                    .map_err(|e| format!("--interactions: {e}"))?;
            }
            "--duration" => {
                duration = value(&mut it, "--duration")?
                    .parse()
                    .map_err(|e| format!("--duration: {e}"))?;
            }
            "--half-width" => {
                half_width = value(&mut it, "--half-width")?
                    .parse()
                    .map_err(|e| format!("--half-width: {e}"))?;
            }
            "--level" => {
                level = value(&mut it, "--level")?
                    .parse()
                    .map_err(|e| format!("--level: {e}"))?;
            }
            "--variant" => variant = value(&mut it, "--variant")?,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    Ok(Args {
        out: out.ok_or_else(|| format!("--out is required\n{USAGE}"))?,
        fixtures,
        seeds,
        interactions,
        duration,
        half_width,
        level,
        variant,
    })
}

fn scratch_root() -> Result<PathBuf, BenchError> {
    let dir = std::env::temp_dir().join(format!("crawlx-pilot-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| BenchError::Ablation(format!("scratch dir {}: {e}", dir.display())))?;
    Ok(dir)
}

async fn run(args: &Args) -> Result<PilotReport, BenchError> {
    let variant: AblationVariant = ablation::find(&args.variant)
        .ok_or_else(|| BenchError::Ablation(format!("unknown variant {}", args.variant)))?;
    let sets = SeedSets::committed()?;
    let all = sets
        .seeds("pilot")
        .ok_or_else(|| BenchError::Ablation("bench/seeds.toml has no `pilot` suite".to_owned()))?;
    let seeds: Vec<u64> = match args.seeds {
        Some(n) => all.iter().copied().take(n).collect(),
        None => all.to_vec(),
    };
    if seeds.len() < 2 {
        return Err(BenchError::Ablation(
            "the pilot needs at least two seeds".to_owned(),
        ));
    }
    let gym = GymServer::start(
        "127.0.0.1:0"
            .parse()
            .map_err(|e| BenchError::Ablation(format!("bind: {e}")))?,
    )
    .await?;
    let scratch = scratch_root()?;
    let mut fixtures = Vec::with_capacity(args.fixtures.len());
    let mut seeds_needed = 2;
    for id in &args.fixtures {
        let manifest = FixtureManifest::embedded(id)?;
        let executor = WorkerExecutor {
            gym: &gym,
            profile: SafetyProfile::TestEnvironment,
            interactions: args.interactions,
            duration_seconds: args.duration,
            artifacts: scratch.join(id),
            model: None,
        };
        let runner = AblationRunner::new(&executor);
        eprintln!("pilot: {id}: {} seeds of {}", seeds.len(), variant.id);
        let report = runner
            .run(std::slice::from_ref(&variant), &manifest, &seeds)
            .await?;
        let trusted: Vec<f64> = report
            .outcomes
            .iter()
            .map(|o| o.scorecard.coverage.trusted)
            .collect();
        let t80: Vec<Option<u64>> = report.outcomes.iter().map(|o| o.scorecard.coverage.t80).collect();
        let coverage = pilot_variance(&trusted, args.half_width, args.level)?;
        let reached: Vec<f64> = t80.iter().flatten().map(|v| *v as f64).collect();
        let t80_analysis = (reached.len() >= 2)
            .then(|| pilot_variance(&reached, 1.0, args.level))
            .transpose()?;
        eprintln!(
            "pilot: {id}: mean {:.4} variance {:.6} half-width {:.4} -> seeds needed {}",
            coverage.mean, coverage.variance, coverage.pilot_half_width, coverage.seeds_needed
        );
        seeds_needed = seeds_needed.max(coverage.seeds_needed);
        fixtures.push(FixturePilot {
            fixture: id.clone(),
            seeds: seeds.clone(),
            trusted_coverage: trusted,
            t80,
            coverage,
            t80_analysis,
        });
    }
    gym.shutdown().await;
    if let Err(e) = std::fs::remove_dir_all(&scratch) {
        eprintln!("pilot: could not remove {}: {e}", scratch.display());
    }
    Ok(PilotReport {
        variant: variant.id.to_owned(),
        interactions: args.interactions,
        duration_seconds: args.duration,
        target_half_width: args.half_width,
        level: args.level,
        fixtures,
        seeds_needed,
    })
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    if find_executable().is_none() {
        eprintln!("pilot: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return ExitCode::from(2);
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("pilot: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let report = match rt.block_on(run(&args)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("pilot: {}", e.chain());
            return ExitCode::from(1);
        }
    };
    let json = match serde_json::to_string_pretty(&report) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("pilot: serialize: {e}");
            return ExitCode::from(1);
        }
    };
    if let Some(parent) = args.out.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("pilot: create {}: {e}", parent.display());
            return ExitCode::from(1);
        }
    }
    if let Err(e) = std::fs::write(&args.out, json) {
        eprintln!("pilot: write {}: {e}", args.out.display());
        return ExitCode::from(1);
    }
    let md = args.out.with_extension("md");
    if let Err(e) = std::fs::write(&md, report.render_markdown()) {
        eprintln!("pilot: write {}: {e}", md.display());
        return ExitCode::from(1);
    }
    eprintln!(
        "pilot: wrote {} and {} (seeds needed: {})",
        args.out.display(),
        md.display(),
        report.seeds_needed
    );
    ExitCode::SUCCESS
}
