//! `decision-eval`: the model-in-the-loop evaluation and gate G3.
//!
//! ```text
//! decision-eval ablation --endpoint URL --fixtures IDS --night N --out FILE [--suite nightly]
//!                    [--interactions N] [--duration SECS] [--baseline A9] [--candidate A10]
//! decision-eval shadow   --endpoint URL --fixtures IDS --seeds A,B --shard NAME --out DIR
//!                    [--interactions N] [--duration SECS]
//! decision-eval safety   --endpoint URL --fixtures IDS --out FILE [--profiles read_only,test_environment]
//!                    [--suite nightly] [--seeds N] [--interactions N] [--duration SECS]
//!                    [--forced-acceptance]
//! decision-eval report   --ablation DIR --shadow DIR --safety DIR --metrics FILE --latency FILE
//!                    --heldout IDS --calibration-out FILE --shadow-out FILE --summary-out FILE
//! ```
//!
//! Every phase talks to a running local `decision-serve` (`--endpoint http://127.0.0.1:port/v1/decide`,
//! bundle on CPU or CUDA) through a no-proxy/no-redirect model transport and stores everything in
//! its own PostgreSQL schema (`--database-url`, default `$CRAWLX_TEST_DATABASE_URL`). The
//! phases are single-process (one gym, one Chromium at a time); run several shards in parallel
//! processes over disjoint fixture groups and join them with `report`:
//!
//! * `ablation`: the paired A9-vs-A10 protocol over the seeds of `--suite` for
//!   every fixture, written as one `AblationShard`; `--night` numbers the execution of the
//!   suite (G3 counts consecutive improving nights).
//! * `shadow`: A10 with `system1Mode: shadow` and shortlist recording over `--seeds`; the
//!   joined shadow decisions go to `DIR/<shard>.jsonl`, a summary to `DIR/<shard>.json`.
//! * `safety`: A10 (`advisory`, under a listener-bound controlled evaluation permit) under every
//!   profile of `--profiles` on fixtures with forbidden effects, with the trail verifier on. With
//!   `--forced-acceptance` (any phase) the model's top candidate is accepted on every decision
//!   (the top option is presented at 0.95, `none of these` at 0), so the model influences every
//!   selection it is consulted on: the demanding safety setting, since a model whose shipped
//!   gate never answers cannot exercise the kernel.
//! * `report`: merge the shards into `calibration.json` (the `G3Report` for `gate g3`), the
//!   shadow report and the summary of the paired ablations; `--metrics` is the trainer's
//!   `metrics.json` (ECE and sample count), `--latency` the latency evidence (`gpu.p95_ms`).

use clap::{Args, Parser, Subcommand};
use crawlx_bench::ablation::{self, VariantExecutor as _};
use crawlx_bench::decision_eval::{EngineStats, ShadowDecision};
use crawlx_bench::decision_report::{
    assemble, AblationShard, AssembleConfig, FailedRun, SafetyRun, SafetyShard, ShadowShard,
};
use crawlx_bench::decision_rig::{paired_runs, scratch_dir, DecisionRig, RigConfig, RigExecutor};
use crawlx_bench::error::chain;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::scorecard::Scorecard;
use crawlx_bench::stats::SeedSets;
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{SafetyProfile, System1Mode};
use crawlx_worker::ShortlistRecording;
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "decision-eval",
    version,
    about = "Model-in-the-loop evaluation of the typed ranker"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The served model and the database every phase but `report` needs.
#[derive(Args, Debug)]
struct RigArgs {
    /// `http://host:port/v1/decide` of a running `decision-serve`.
    #[arg(long)]
    endpoint: String,
    /// PostgreSQL URL of the rig's schema.
    #[arg(long, env = "CRAWLX_TEST_DATABASE_URL")]
    database_url: String,
    /// Per-call time budget of the model engine in milliseconds.
    #[arg(long, default_value_t = 1500)]
    timeout_ms: u64,
    /// Accept the model's top candidate on every decision (`ForcedChoice`), so the model
    /// influences every selection it is consulted on (the demanding safety setting).
    #[arg(long)]
    forced_acceptance: bool,
}

/// Arguments of `ablation`.
#[derive(Args, Debug)]
struct AblationArgs {
    #[command(flatten)]
    rig: RigArgs,
    /// Fixture ids.
    #[arg(long, value_delimiter = ',', required = true)]
    fixtures: Vec<String>,
    /// Seed suite of `bench/seeds.toml`.
    #[arg(long, default_value = "nightly")]
    suite: String,
    /// Execution of the suite this shard belongs to (1-based).
    #[arg(long, default_value_t = 1)]
    night: u32,
    /// Interaction budget per run.
    #[arg(long, default_value_t = 60)]
    interactions: u32,
    /// Wall-clock limit per run in seconds.
    #[arg(long, default_value_t = 180)]
    duration: u32,
    /// Baseline row.
    #[arg(long, default_value = "A9")]
    baseline: String,
    /// Candidate row (must request the model).
    #[arg(long, default_value = "A10")]
    candidate: String,
    /// Shard file (JSON).
    #[arg(long)]
    out: PathBuf,
}

/// Arguments of `shadow`.
#[derive(Args, Debug)]
struct ShadowArgs {
    #[command(flatten)]
    rig: RigArgs,
    /// Fixture ids.
    #[arg(long, value_delimiter = ',', required = true)]
    fixtures: Vec<String>,
    /// Crawl seeds.
    #[arg(long, value_delimiter = ',', required = true)]
    seeds: Vec<u64>,
    /// Interaction budget per run.
    #[arg(long, default_value_t = 120)]
    interactions: u32,
    /// Wall-clock limit per run in seconds.
    #[arg(long, default_value_t = 90)]
    duration: u32,
    /// Shard name (files `<shard>.jsonl` and `<shard>.json`).
    #[arg(long, default_value = "shard")]
    shard: String,
    /// Output directory.
    #[arg(long)]
    out: PathBuf,
}

/// Arguments of `safety`.
#[derive(Args, Debug)]
struct SafetyArgs {
    #[command(flatten)]
    rig: RigArgs,
    /// Fixture ids.
    #[arg(long, value_delimiter = ',', required = true)]
    fixtures: Vec<String>,
    /// Safety profiles (`read_only`, `test_environment`).
    #[arg(long, value_delimiter = ',', default_value = "read_only,test_environment")]
    profiles: Vec<String>,
    /// Seed suite of `bench/seeds.toml`.
    #[arg(long, default_value = "nightly")]
    suite: String,
    /// Use the first N seeds of the suite.
    #[arg(long, default_value_t = 4)]
    seeds: usize,
    /// Interaction budget per run.
    #[arg(long, default_value_t = 40)]
    interactions: u32,
    /// Wall-clock limit per run in seconds.
    #[arg(long, default_value_t = 120)]
    duration: u32,
    /// Shard file (JSON).
    #[arg(long)]
    out: PathBuf,
}

/// Arguments of `report`.
#[derive(Args, Debug)]
struct ReportArgs {
    /// Directory of `AblationShard` files.
    #[arg(long)]
    ablation: PathBuf,
    /// Directory of shadow shards (`.json` + `.jsonl`).
    #[arg(long)]
    shadow: PathBuf,
    /// Directory of `SafetyShard` files.
    #[arg(long)]
    safety: PathBuf,
    /// `metrics.json` of the trainer.
    #[arg(long)]
    metrics: PathBuf,
    /// Latency evidence JSON with `gpu.p95_ms`.
    #[arg(long)]
    latency: PathBuf,
    /// Held-out fixtures of the shadow report.
    #[arg(long, value_delimiter = ',', required = true)]
    heldout: Vec<String>,
    /// Where the `G3Report` goes.
    #[arg(long)]
    calibration_out: PathBuf,
    /// Where the shadow report goes.
    #[arg(long)]
    shadow_out: PathBuf,
    /// Where the evidence summary (ablation, safety, verdict) goes.
    #[arg(long)]
    summary_out: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Paired A9-vs-A10 runs over the seeds of a suite.
    Ablation(AblationArgs),
    /// Shadow-mode runs recording shortlists and the model's answers.
    Shadow(ShadowArgs),
    /// Model-in-the-loop runs on the fixtures with forbidden effects.
    Safety(SafetyArgs),
    /// Merge the shards into the G3 report, the shadow report and the ablation summary.
    Report(ReportArgs),
}

fn rig_config(rig: &RigArgs, tag: &str) -> RigConfig {
    RigConfig {
        database_url: rig.database_url.clone(),
        endpoint: rig.endpoint.clone(),
        timeout: Duration::from_millis(rig.timeout_ms),
        forced_choice: rig.forced_acceptance,
        scratch: scratch_dir(&std::env::temp_dir(), tag),
    }
}

fn manifests(ids: &[String]) -> Result<Vec<FixtureManifest>, String> {
    ids.iter()
        .map(|f| FixtureManifest::embedded(f).map_err(|e| chain(&e)))
        .collect()
}

fn suite_seeds(suite: &str) -> Result<Vec<u64>, String> {
    let sets = SeedSets::committed().map_err(|e| chain(&e))?;
    sets.seeds(suite)
        .map(<[u64]>::to_vec)
        .ok_or_else(|| format!("bench/seeds.toml has no `{suite}` suite"))
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

fn profile_of(name: &str) -> Result<SafetyProfile, String> {
    match name {
        "read_only" => Ok(SafetyProfile::ReadOnly),
        "test_environment" => Ok(SafetyProfile::TestEnvironment),
        other => Err(format!(
            "unknown profile `{other}` (read_only or test_environment)"
        )),
    }
}

async fn ablation_phase(args: AblationArgs) -> Result<(), String> {
    let AblationArgs {
        rig,
        fixtures,
        suite,
        night,
        interactions,
        duration,
        baseline,
        candidate,
        out,
    } = args;
    let base = ablation::find(&baseline).ok_or_else(|| format!("unknown variant {baseline}"))?;
    let cand = ablation::find(&candidate).ok_or_else(|| format!("unknown variant {candidate}"))?;
    if cand.model == System1Mode::Off {
        return Err(format!("variant {candidate} does not request the model"));
    }
    let seeds = suite_seeds(&suite)?;
    let manifests = manifests(&fixtures)?;
    let gym = GymServer::start_evaluation().await.map_err(|e| chain(&e))?;
    let rig = DecisionRig::open(&rig_config(&rig, "ablation"), &gym)
        .await
        .map_err(|e| e.chain())?;
    let mut executor = RigExecutor::new(&rig, &gym, SafetyProfile::TestEnvironment, interactions, duration);
    executor.ceiling = cand.model;
    let mut shard = AblationShard {
        night,
        suite,
        baseline: base.id.to_owned(),
        candidate: cand.id.to_owned(),
        interactions,
        duration_seconds: duration,
        fixtures: fixtures.clone(),
        seeds: seeds.clone(),
        runs: Vec::new(),
        failed: Vec::new(),
        captures: Vec::new(),
        engine: EngineStats::default(),
        model: rig.model_id().to_string(),
    };
    for manifest in &manifests {
        let started = Instant::now();
        let (runs, failed) = paired_runs(&executor, &base, &cand, manifest, &seeds).await;
        let gain: f64 = runs.iter().map(|r| r.candidate - r.baseline).sum::<f64>() / runs.len().max(1) as f64;
        eprintln!(
            "decision-eval: ablation night {night} {}: {} pairs, {} failed, mean trusted-coverage gain {gain:+.4} in {:.0}s",
            manifest.id,
            runs.len(),
            failed.len(),
            started.elapsed().as_secs_f64()
        );
        shard.runs.extend(runs);
        shard
            .failed
            .extend(failed.into_iter().map(|(seed, error)| FailedRun {
                fixture: manifest.id.clone(),
                seed,
                error,
            }));
        shard.captures.extend(executor.take_captures());
        shard.engine = rig.engine().stats();
        write_json(&out, &shard)?;
    }
    drop(executor);
    gym.shutdown().await;
    rig.close().await.map_err(|e| e.chain())?;
    eprintln!("decision-eval: wrote {}", out.display());
    Ok(())
}

async fn shadow_phase(args: ShadowArgs) -> Result<(), String> {
    let ShadowArgs {
        rig,
        fixtures,
        seeds,
        interactions,
        duration,
        shard,
        out,
    } = args;
    let mut variant = ablation::find("A10").ok_or("the ablation matrix has no A10 row")?;
    variant.model = System1Mode::Shadow;
    let manifests = manifests(&fixtures)?;
    std::fs::create_dir_all(&out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let jsonl = out.join(format!("{shard}.jsonl"));
    let mut sink = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&jsonl)
        .map_err(|e| format!("open {}: {e}", jsonl.display()))?;
    let gym = GymServer::start_evaluation().await.map_err(|e| chain(&e))?;
    let rig = DecisionRig::open(&rig_config(&rig, &format!("shadow-{shard}")), &gym)
        .await
        .map_err(|e| e.chain())?;
    let mut executor = RigExecutor::new(&rig, &gym, SafetyProfile::TestEnvironment, interactions, duration);
    executor.ceiling = System1Mode::Shadow;
    executor.recording = Some(ShortlistRecording::recording_only());
    let mut summary = ShadowShard {
        shard: shard.clone(),
        fixtures: fixtures.clone(),
        seeds: seeds.clone(),
        decisions: 0,
        failed: Vec::new(),
        captures: Vec::new(),
        engine: EngineStats::default(),
        model: rig.model_id().to_string(),
    };
    for manifest in &manifests {
        for &seed in &seeds {
            let started = Instant::now();
            match executor.execute(&variant, manifest, seed).await {
                Ok(_) => {
                    let decisions: Vec<ShadowDecision> = executor.take_shadow();
                    let mut buf = Vec::new();
                    for d in &decisions {
                        serde_json::to_writer(&mut buf, d).map_err(|e| format!("serialize: {e}"))?;
                        buf.push(b'\n');
                    }
                    sink.write_all(&buf)
                        .and_then(|()| sink.flush())
                        .map_err(|e| format!("write {}: {e}", jsonl.display()))?;
                    summary.decisions += decisions.len() as u64;
                    summary.captures.extend(executor.take_captures());
                    eprintln!(
                        "decision-eval: shadow {} seed {seed}: {} decisions in {:.1}s (shard total {})",
                        manifest.id,
                        decisions.len(),
                        started.elapsed().as_secs_f64(),
                        summary.decisions
                    );
                }
                Err(e) => {
                    eprintln!(
                        "decision-eval: shadow {} seed {seed}: failed: {}",
                        manifest.id,
                        e.chain()
                    );
                    summary.failed.push(FailedRun {
                        fixture: manifest.id.clone(),
                        seed,
                        error: e.chain(),
                    });
                }
            }
            summary.engine = rig.engine().stats();
            write_json(&out.join(format!("{shard}.json")), &summary)?;
        }
    }
    drop(executor);
    gym.shutdown().await;
    rig.close().await.map_err(|e| e.chain())?;
    eprintln!(
        "decision-eval: shadow shard {shard}: {} decisions in {}",
        summary.decisions,
        jsonl.display()
    );
    Ok(())
}

async fn safety_phase(args: SafetyArgs) -> Result<(), String> {
    let SafetyArgs {
        rig,
        fixtures,
        profiles,
        suite,
        seeds,
        interactions,
        duration,
        out,
    } = args;
    let variant = ablation::find("A10").ok_or("the ablation matrix has no A10 row")?;
    let seeds: Vec<u64> = suite_seeds(&suite)?.into_iter().take(seeds).collect();
    let profiles: Vec<(String, SafetyProfile)> = profiles
        .iter()
        .map(|p| profile_of(p).map(|v| (p.clone(), v)))
        .collect::<Result<_, _>>()?;
    let manifests = manifests(&fixtures)?;
    let gym = GymServer::start_evaluation().await.map_err(|e| chain(&e))?;
    let forced_acceptance = rig.forced_acceptance;
    let rig = DecisionRig::open(&rig_config(&rig, "safety"), &gym)
        .await
        .map_err(|e| e.chain())?;
    let mut shard = SafetyShard {
        variant: variant.id.to_owned(),
        forced_acceptance,
        interactions,
        runs: Vec::new(),
        failed: Vec::new(),
        engine: EngineStats::default(),
        model: rig.model_id().to_string(),
    };
    for (profile_name, profile) in &profiles {
        let mut executor = RigExecutor::new(&rig, &gym, *profile, interactions, duration);
        executor.ceiling = variant.model;
        executor.verify_trail = true;
        for manifest in &manifests {
            for &seed in &seeds {
                let started = Instant::now();
                match executor.execute(&variant, manifest, seed).await {
                    Ok(done) => {
                        let card = Scorecard::compute(manifest, &done.rows, &done.ledger);
                        let capture = executor
                            .take_captures()
                            .pop()
                            .ok_or("the executor kept no capture")?;
                        eprintln!(
                            "decision-eval: safety {profile_name} {} seed {seed}: {} executed, {} unauthorized, {} kernel denials, {} model calls ({} selected) in {:.1}s",
                            manifest.id,
                            card.safety.executed,
                            card.safety.unauthorized,
                            capture.policy_blocked,
                            capture.model_calls,
                            capture.model_selected,
                            started.elapsed().as_secs_f64()
                        );
                        shard.runs.push(SafetyRun {
                            fixture: manifest.id.clone(),
                            profile: profile_name.clone(),
                            seed,
                            executed: card.safety.executed,
                            unauthorized: card.safety.unauthorized,
                            violations: card.safety.violations,
                            capture,
                        });
                    }
                    Err(e) => {
                        eprintln!(
                            "decision-eval: safety {profile_name} {} seed {seed}: failed: {}",
                            manifest.id,
                            e.chain()
                        );
                        shard.failed.push(FailedRun {
                            fixture: manifest.id.clone(),
                            seed,
                            error: e.chain(),
                        });
                    }
                }
                shard.engine = rig.engine().stats();
                write_json(&out, &shard)?;
            }
        }
    }
    gym.shutdown().await;
    rig.close().await.map_err(|e| e.chain())?;
    eprintln!("decision-eval: wrote {}", out.display());
    Ok(())
}

fn read_value(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn report_phase(args: &ReportArgs) -> Result<(), String> {
    let metrics = read_value(&args.metrics)?;
    let latency = read_value(&args.latency)?;
    let ece = metrics["g3"]["ece"]
        .as_f64()
        .ok_or("metrics.json has no g3.ece")?;
    let samples = metrics["g3"]["calibration_samples"]
        .as_u64()
        .ok_or("metrics.json has no g3.calibration_samples")?;
    let warm = latency["gpu"]["p95_ms"]
        .as_f64()
        .ok_or("latency evidence has no gpu.p95_ms")?;
    let cfg = AssembleConfig {
        calibration_samples: samples,
        ece,
        warm_p95_ms: warm,
        heldout_fixtures: args.heldout.iter().cloned().collect::<BTreeSet<_>>(),
    };
    let evidence = assemble(&args.ablation, &args.shadow, &args.safety, &cfg).map_err(|e| e.chain())?;
    write_json(&args.calibration_out, &evidence.g3)?;
    write_json(
        &args.shadow_out,
        &serde_json::json!({
            "schema": "decision-shadow-report/v1",
            "models": evidence.models,
            "promotion_floor": {
                "decisions": 20_000,
                "fixtures": 10,
                "decisions_met": evidence.shadow_all.decisions >= 20_000,
                "fixtures_met": evidence.shadow_all.fixtures >= 10,
            },
            "all": evidence.shadow_all,
            "heldout_fixtures": evidence.heldout_fixtures,
            "heldout": evidence.shadow_heldout,
        }),
    )?;
    write_json(&args.summary_out, &evidence)?;
    print!("{}", evidence.verdict.render());
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let needs_chromium = !matches!(cli.command, Command::Report(_));
    if needs_chromium && find_executable().is_none() {
        eprintln!("decision-eval: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return ExitCode::from(2);
    }
    let result = match cli.command {
        Command::Report(args) => report_phase(&args),
        command => match tokio::runtime::Runtime::new() {
            Ok(rt) => rt.block_on(async {
                match command {
                    Command::Ablation(args) => ablation_phase(args).await,
                    Command::Shadow(args) => shadow_phase(args).await,
                    Command::Safety(args) => safety_phase(args).await,
                    Command::Report(args) => report_phase(&args),
                }
            }),
            Err(e) => Err(format!("runtime: {e}")),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("decision-eval: {msg}");
            ExitCode::from(1)
        }
    }
}
