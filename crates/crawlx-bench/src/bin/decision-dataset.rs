//! `decision-dataset`: build the labelled shortlist dataset of the typed ranker.
//!
//! ```text
//! decision-dataset collect  --out DIR [--fixtures IDS|all] --seeds A,B,C [--interactions N]
//!                       [--duration SECS] [--no-explore] [--shard NAME]
//! decision-dataset finalize --out DIR [--val-n N] [--test-n N] [--val-families IDS] [--test-families IDS]
//!                       [--min-decisions N]
//! ```
//!
//! `collect` crawls the gym fixtures on real Chromium under the production strategy set (A9 plus
//! System 1 in `shadow`) with shortlist recording on, and appends one JSON line per decision to
//! `DIR/raw/<shard>.jsonl` after every run, so several shards can run as parallel processes and a
//! killed run loses only its own rows. `finalize` joins the shards, splits whole fixture families
//! into `train`/`val`/`test` and writes `DIR/{train,val,test}.jsonl` plus `manifest.json`.
//!
//! Collection requires the normal authenticated deployment gates. A failed worker run writes no
//! decision rows; any failed run makes `collect` exit nonzero and report an incomplete shard.
//! Rows from other successful runs remain available for explicit operator inspection.

use clap::{Parser, Subcommand};
use crawlx_bench::decision_dataset::{read_shards, record_run, write_dataset, CollectConfig, SplitPlan};
use crawlx_bench::error::chain;
use crawlx_bench::gym::manifest::{ExpectedClass, FixtureManifest};
use crawlx_bench::gym::GymServer;
use crawlx_browser::launch::find_executable;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "decision-dataset",
    version,
    about = "Labelled shortlist dataset of the typed ranker"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Crawl gym fixtures and record one row per System 1 decision.
    Collect {
        /// Dataset directory; raw shards go to `<out>/raw/`.
        #[arg(long)]
        out: PathBuf,
        /// Fixture ids, or `all` for every fixture that has actionable controls.
        #[arg(long, value_delimiter = ',', default_value = "all")]
        fixtures: Vec<String>,
        /// Crawl seeds (comma separated).
        #[arg(long, value_delimiter = ',', required = true)]
        seeds: Vec<u64>,
        /// Interaction budget of each run.
        #[arg(long, default_value_t = 120)]
        interactions: u32,
        /// Wall-clock limit of each run in seconds.
        #[arg(long, default_value_t = 90)]
        duration: u32,
        /// Execute the arbiter's pick instead of a seeded uniform draw from the shortlist.
        #[arg(long)]
        no_explore: bool,
        /// Shard name (the raw file is `<shard>.jsonl`).
        #[arg(long, default_value = "shard")]
        shard: String,
    },
    /// Join the raw shards, split by family and write the dataset files.
    Finalize {
        /// Dataset directory holding `raw/`.
        #[arg(long)]
        out: PathBuf,
        /// Families assigned to `val` when `--val-families` is not given.
        #[arg(long, default_value_t = 3)]
        val_n: usize,
        /// Families assigned to `test` when `--test-families` is not given.
        #[arg(long, default_value_t = 6)]
        test_n: usize,
        /// Explicit `val` families.
        #[arg(long, value_delimiter = ',')]
        val_families: Vec<String>,
        /// Explicit `test` families.
        #[arg(long, value_delimiter = ',')]
        test_families: Vec<String>,
        /// Families with fewer decisions are left out of the dataset entirely.
        #[arg(long, default_value_t = 100)]
        min_decisions: usize,
    },
}

fn interactive_fixtures() -> Result<Vec<FixtureManifest>, String> {
    let all = FixtureManifest::embedded_all().map_err(|e| chain(&e))?;
    Ok(all
        .into_iter()
        .filter(|m| m.controls.iter().any(|c| c.expected == ExpectedClass::Actionable))
        .collect())
}

async fn collect(
    out: &Path,
    fixtures: &[String],
    seeds: &[u64],
    cfg: CollectConfig,
    shard: &str,
) -> Result<(), String> {
    let manifests: Vec<FixtureManifest> = if fixtures.iter().any(|f| f == "all") {
        interactive_fixtures()?
    } else {
        fixtures
            .iter()
            .map(|f| FixtureManifest::embedded(f).map_err(|e| chain(&e)))
            .collect::<Result<_, _>>()?
    };
    let raw = out.join("raw");
    std::fs::create_dir_all(&raw).map_err(|e| format!("create {}: {e}", raw.display()))?;
    let path = raw.join(format!("{shard}.jsonl"));
    let mut sink = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let scratch = std::env::temp_dir().join(format!("crawlx-decision-dataset-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|e| format!("create {}: {e}", scratch.display()))?;
    let addr = "127.0.0.1:0".parse().map_err(|e| format!("bind: {e}"))?;
    let gym = GymServer::start(addr).await.map_err(|e| chain(&e))?;
    let mut total = 0_usize;
    let mut failed_runs = 0usize;
    for manifest in &manifests {
        for &seed in seeds {
            let started = Instant::now();
            let artifacts = scratch.join(format!("{}-{seed}", manifest.id));
            match record_run(&gym, manifest, seed, &cfg, &artifacts).await {
                Ok(rows) => {
                    let mut buf = Vec::new();
                    for row in &rows {
                        serde_json::to_writer(&mut buf, row).map_err(|e| format!("serialize: {e}"))?;
                        buf.push(b'\n');
                    }
                    sink.write_all(&buf)
                        .map_err(|e| format!("write {}: {e}", path.display()))?;
                    sink.flush()
                        .map_err(|e| format!("flush {}: {e}", path.display()))?;
                    total += rows.len();
                    eprintln!(
                        "decision-dataset: {} seed {seed}: {} decisions in {:.1}s (shard total {total})",
                        manifest.id,
                        rows.len(),
                        started.elapsed().as_secs_f64()
                    );
                }
                Err(e) => {
                    failed_runs = failed_runs.saturating_add(1);
                    eprintln!(
                        "decision-dataset: {} seed {seed}: failed: {}",
                        manifest.id,
                        chain(&e)
                    );
                }
            }
            // best effort: the scratch artifacts of a finished run are not needed again
            let _ = std::fs::remove_dir_all(&artifacts);
        }
    }
    gym.shutdown().await;
    let _ = std::fs::remove_dir_all(&scratch);
    eprintln!(
        "decision-dataset: shard {shard}: {total} decisions in {}",
        path.display()
    );
    if failed_runs == 0 {
        Ok(())
    } else {
        Err(format!(
            "{failed_runs} dataset collection runs failed; shard is incomplete"
        ))
    }
}

fn finalize(
    out: &Path,
    val_n: usize,
    test_n: usize,
    val_families: &[String],
    test_families: &[String],
    min_decisions: usize,
) -> Result<(), String> {
    let rows = read_shards(&out.join("raw")).map_err(|e| chain(&e))?;
    let mut per_family: BTreeMap<String, usize> = BTreeMap::new();
    for r in &rows {
        *per_family.entry(r.family.clone()).or_default() += 1;
    }
    let keep: BTreeSet<String> = per_family
        .iter()
        .filter(|(_, n)| **n >= min_decisions)
        .map(|(f, _)| f.clone())
        .collect();
    let plan = if val_families.is_empty() && test_families.is_empty() {
        SplitPlan::by_digest(keep.iter().map(String::as_str), val_n, test_n)
    } else {
        SplitPlan {
            val: val_families.iter().cloned().collect(),
            test: test_families.iter().cloned().collect(),
        }
    };
    let rows: Vec<_> = rows.into_iter().filter(|r| keep.contains(&r.family)).collect();
    let manifest = write_dataset(out, rows, &plan).map_err(|e| chain(&e))?;
    for (name, s) in &manifest.splits {
        eprintln!(
            "decision-dataset: {name}: {} decisions, {} families, {} candidates ({} labelled, {} positive), {} seeds",
            s.decisions,
            s.families.len(),
            s.candidates,
            s.labelled,
            s.positive,
            s.seeds.len()
        );
    }
    eprintln!(
        "decision-dataset: {} decisions in {}",
        manifest.decisions,
        out.display()
    );
    let dropped: Vec<_> = per_family.iter().filter(|(f, _)| !keep.contains(*f)).collect();
    if !dropped.is_empty() {
        eprintln!("decision-dataset: left out (fewer than {min_decisions} decisions): {dropped:?}");
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Collect {
            out,
            fixtures,
            seeds,
            interactions,
            duration,
            no_explore,
            shard,
        } => {
            if find_executable().is_none() {
                eprintln!("decision-dataset: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
                return ExitCode::from(2);
            }
            let cfg = CollectConfig {
                interactions,
                duration_seconds: duration,
                explore: !no_explore,
                ..CollectConfig::default()
            };
            match tokio::runtime::Runtime::new() {
                Ok(rt) => rt.block_on(collect(&out, &fixtures, &seeds, cfg, &shard)),
                Err(e) => Err(format!("runtime: {e}")),
            }
        }
        Command::Finalize {
            out,
            val_n,
            test_n,
            val_families,
            test_families,
            min_decisions,
        } => finalize(&out, val_n, test_n, &val_families, &test_families, min_decisions),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("decision-dataset: {msg}");
            ExitCode::from(1)
        }
    }
}
