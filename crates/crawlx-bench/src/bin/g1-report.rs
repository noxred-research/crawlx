//! `g1-report`: assemble the [`G1Report`] the `gate-g1` CI job feeds to `gate g1`.
//!
//! ```text
//! g1-report --out bench/out/g1-report.json [--fixtures d1,g01,...] [--seed N]
//!           [--interactions N] [--replay-paths N] [--chaos-report FILE]
//! ```
//!
//! For every fixture of the D1 set the worker crawls the live gym through real Chromium
//! (`CRAWLX_CHROMIUM_PATH`) twice with the same seed; the first run's scorecard carries the
//! ordered action/value trace against the second. Every recorded path of the first run
//! is replayed in `verify` mode, including paths ending in failed actions. `--replay-paths`
//! caps the sweep for informational use only and cannot pass G1. `--chaos-report` embeds
//! the completed suite artifact produced by `chaos-report`; missing evidence fails G1.

use crawlx_bench::ablation;
use crawlx_bench::error::BenchError;
use crawlx_bench::gates::{ChaosEvidence, G1Report, G1RunEvidence};
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::scorecard::Scorecard;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, rows_from_report, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::ActionStatus;
use crawlx_storage::MemoryStore;
use crawlx_worker::action_trace::{ActionTrace, TraceStep};
use crawlx_worker::replay::{ReplayMode, ReplayPlan, ReplayRunner};
use crawlx_worker::{run_local_with, DriverConfig, LocalRun, RunReport, StaticAuthorizationSource, Stores};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "usage: g1-report --out FILE [--fixtures IDS] [--seed N] [--interactions N] [--replay-paths N] [--chaos-report FILE]\n\
  --out FILE          where to write the G1Report JSON\n\
  --fixtures IDS      comma-separated gym fixture ids (default: the D1 set)\n\
  --seed N            crawl seed used for both runs of every fixture (default 7)\n\
  --interactions N    interaction budget per run (default 40)\n\
  --replay-paths N    cap replay paths per fixture (informational only; default replays every path)\n\
  --chaos-report FILE completed suite artifact from chaos-report (required to pass G1)";

/// The D1 set: the SPA fixture plus the G01–G08 gym pages.
const D1_SET: [&str; 9] = ["d1", "g01", "g02", "g03", "g04", "g05", "g06", "g07", "g08"];

/// Ablation row the gate runs: the full discovery ladder with the layered `W` queue (`A4`).
/// Not `A7`/`A8`: the enablement and state-novelty strategies are themselves gated on
/// `g1.passed`, so the gate run must not depend on them.
const VARIANT: &str = "A4";

/// Gym fixture controls carry no semantics, so `read_only` denies every unclassified button by
/// design (fail closed, as `worker_e2e` notes); the gate crawls under `test_environment` and
/// the `unauthorized_actions == 0` criterion is judged there.
const PROFILE: SafetyProfile = SafetyProfile::TestEnvironment;

struct Args {
    out: PathBuf,
    fixtures: Vec<String>,
    seed: u64,
    interactions: u32,
    replay_paths: Option<usize>,
    chaos_report: Option<PathBuf>,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut out = None;
    let mut fixtures: Vec<String> = D1_SET.iter().map(|s| (*s).to_owned()).collect();
    let mut seed = 7;
    let mut interactions = 40;
    let mut replay_paths = None;
    let mut chaos_report = None;
    let value = |it: &mut dyn Iterator<Item = String>, flag: &str| {
        it.next().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = Some(PathBuf::from(value(&mut it, "--out")?)),
            "--fixtures" => {
                fixtures = value(&mut it, "--fixtures")?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            "--seed" => {
                seed = value(&mut it, "--seed")?
                    .parse()
                    .map_err(|e| format!("--seed: {e}"))?
            }
            "--interactions" => {
                interactions = value(&mut it, "--interactions")?
                    .parse()
                    .map_err(|e| format!("--interactions: {e}"))?;
            }
            "--replay-paths" => {
                replay_paths = Some(
                    value(&mut it, "--replay-paths")?
                        .parse()
                        .map_err(|e| format!("--replay-paths: {e}"))?,
                );
            }
            "--chaos-report" => chaos_report = Some(PathBuf::from(value(&mut it, "--chaos-report")?)),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    Ok(Args {
        out: out.ok_or_else(|| format!("--out is required\n{USAGE}"))?,
        fixtures,
        seed,
        interactions,
        replay_paths,
        chaos_report,
    })
}

/// One worker run of `manifest` on `gym`; the stores stay alive so the run can be replayed.
async fn crawl_once(
    gym: &GymHandle,
    manifest: &FixtureManifest,
    args: &Args,
    artifacts: &Path,
) -> Result<(RunReport, Stores, crawlx_worker::WorkerConfig, Vec<TraceStep>), BenchError> {
    let variant =
        ablation::find(VARIANT).ok_or_else(|| BenchError::Ablation(format!("no variant {VARIANT}")))?;
    gym.reset(args.seed);
    let mut req = crawl_request(manifest, &gym.base_url, args.seed, PROFILE)?;
    variant.apply(&mut req);
    req.limits.interactions = args.interactions;
    // G1 compares action traces, not how many actions fit the gym's 20-second smoke
    // deadline. Browser pacing alone needs 20 seconds for the default 40 effects.
    req.limits.duration_seconds = args.interactions.saturating_mul(10).saturating_add(30);
    req.limits.urls = 200;
    let mut cfg = worker_config(manifest, artifacts)?;
    let trace = Arc::new(ActionTrace::default());
    cfg.action_trace = Some(Arc::clone(&trace));
    let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), artifacts).await?;
    let mut driver = DriverConfig::default();
    driver.exploration.queue = variant.queue_cfg();
    let mut local = authorize_fixture(
        LocalRun::new(req, cfg.clone())
            .with_driver(driver)
            .with_stores(stores.clone()),
    );
    if let Some(record) = local.authorization.as_ref() {
        stores = stores.with_authorization_source(Arc::new(StaticAuthorizationSource::new(record.clone())));
        local = local.with_stores(stores.clone());
    }
    let report = run_local_with(local).await?;
    let performed = trace.take();
    for step in &performed {
        if !report.actions.iter().any(|row| {
            row.id == step.action
                && row.session == step.session
                && row.key == step.step.key
                && row.intended_at.is_some()
        }) {
            return Err(BenchError::Gate(
                "performed trace does not join its journal row".to_owned(),
            ));
        }
    }
    cfg.action_trace = None; // replay does not extend the original run's evidence
    Ok((
        report,
        stores,
        cfg,
        performed.into_iter().map(|entry| entry.step).collect(),
    ))
}

/// `(matched, replayed)` over every performed path, or an explicitly informational cap.
async fn replay_paths(
    report: &RunReport,
    stores: &Stores,
    cfg: &crawlx_worker::WorkerConfig,
    limit: Option<usize>,
    gym: &GymHandle,
    seed: u64,
) -> Result<(usize, usize), BenchError> {
    let mut matched = 0;
    let mut total = 0;
    let targets = report
        .actions
        .iter()
        .filter(|a| matches!(a.status, ActionStatus::Succeeded | ActionStatus::Failed))
        .take(limit.unwrap_or(usize::MAX));
    for action in targets {
        eprintln!(
            "g1-report: replay source action {} (sequence {})",
            action.id, action.seq
        );
        gym.reset(seed); // every path starts from the same fixture snapshot as the recorded run
        let plan = ReplayPlan::load(stores, report.run_id, action.id).await?;
        let out = ReplayRunner::run(cfg.clone(), plan, ReplayMode::Verify, None, None).await?;
        total += 1;
        if out.ok {
            matched += 1;
        } else if let Some(step) = out.steps.iter().find(|s| !s.verdict.ok()) {
            // the first non-ok step explains the mismatch (CI reads this from the job log)
            eprintln!(
                "g1-report: replay of action {} did not match: step {} {} -> {:?}",
                action.id, step.seq, step.kind, step.verdict
            );
        } else {
            eprintln!(
                "g1-report: replay of action {} executed only {} step(s) of its plan",
                action.id,
                out.steps.len()
            );
        }
    }
    Ok((matched, total))
}

/// Scratch root for the worker's artifact stores; removed when the report is assembled.
fn scratch_root() -> Result<PathBuf, BenchError> {
    let dir = std::env::temp_dir().join(format!("crawlx-g1-report-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| BenchError::Ablation(format!("scratch dir {}: {e}", dir.display())))?;
    Ok(dir)
}

async fn assemble(args: &Args) -> Result<G1Report, BenchError> {
    let gym = GymServer::start(
        "127.0.0.1:0"
            .parse()
            .map_err(|e| BenchError::Ablation(format!("bind: {e}")))?,
    )
    .await?;
    let scratch = scratch_root()?;
    let out = assemble_in(args, &gym, &scratch).await;
    if let Err(e) = std::fs::remove_dir_all(&scratch) {
        eprintln!("g1-report: could not remove {}: {e}", scratch.display());
    }
    out
}

async fn assemble_in(args: &Args, gym: &GymHandle, scratch: &Path) -> Result<G1Report, BenchError> {
    let mut scorecards = Vec::with_capacity(args.fixtures.len());
    let mut runs = Vec::with_capacity(args.fixtures.len());
    let mut matched = 0;
    let mut replayed = 0;
    for id in &args.fixtures {
        let manifest = FixtureManifest::embedded(id)?;
        eprintln!("g1-report: {id}: run 1");
        let (first, stores, cfg, first_trace) =
            crawl_once(gym, &manifest, args, &scratch.join(id).join("1")).await?;
        let rows = rows_from_report(&first, &manifest, args.seed, VARIANT, PROFILE, gym);
        let card = Scorecard::compute(&manifest, &rows, &gym.ledger());
        eprintln!("g1-report: {id}: run 2 (same seed)");
        let (second, _, _, second_trace) =
            crawl_once(gym, &manifest, args, &scratch.join(id).join("2")).await?;
        let rows2 = rows_from_report(&second, &manifest, args.seed, VARIANT, PROFILE, gym);
        let card2 = Scorecard::compute(&manifest, &rows2, &gym.ledger());
        scorecards.push(card.with_run_to_run(&card2));
        eprintln!(
            "g1-report: {id}: replaying {} recorded paths",
            args.replay_paths.map_or_else(
                || "all".to_owned(),
                |count| format!("at most {count} (informational)")
            )
        );
        let (m, t) = replay_paths(&first, &stores, &cfg, args.replay_paths, gym, args.seed).await?;
        matched += m;
        replayed += t;
        eprintln!("g1-report: {id}: replay {m}/{t} matched");
        let mut evidence = G1RunEvidence::new(id.clone(), args.seed);
        evidence.first = first_trace;
        evidence.second = second_trace;
        evidence.first_performed = first
            .actions
            .iter()
            .filter(|row| row.intended_at.is_some())
            .count();
        evidence.second_performed = second
            .actions
            .iter()
            .filter(|row| row.intended_at.is_some())
            .count();
        evidence.replay_recorded = evidence.first_performed;
        evidence.replay_attempted = t;
        evidence.replay_matched = m;
        evidence.informational = args.replay_paths.is_some();
        runs.push(evidence);
    }
    let chaos = args
        .chaos_report
        .as_ref()
        .map(|path| {
            let bytes = std::fs::read(path)
                .map_err(|error| BenchError::Gate(format!("chaos report {}: {error}", path.display())))?;
            serde_json::from_slice::<ChaosEvidence>(&bytes)
                .map_err(|error| BenchError::Gate(format!("chaos report {}: {error}", path.display())))
        })
        .transpose()?;
    eprintln!("g1-report: replay matched {matched}/{replayed}");
    Ok(G1Report {
        scorecards,
        runs,
        chaos,
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
        eprintln!("g1-report: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return ExitCode::from(2);
    }
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("CRAWLX_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .finish();
    if let Err(error) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("g1-report: tracing: {error}");
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("g1-report: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let report = match rt.block_on(assemble(&args)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("g1-report: {}", e.chain());
            return ExitCode::from(1);
        }
    };
    let json = match serde_json::to_string_pretty(&report) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("g1-report: serialize: {e}");
            return ExitCode::from(1);
        }
    };
    if let Some(parent) = args.out.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("g1-report: create {}: {e}", parent.display());
            return ExitCode::from(1);
        }
    }
    if let Err(e) = std::fs::write(&args.out, json) {
        eprintln!("g1-report: write {}: {e}", args.out.display());
        return ExitCode::from(1);
    }
    eprintln!(
        "g1-report: wrote {} ({} scorecards, {} run evidence pairs)",
        args.out.display(),
        report.scorecards.len(),
        report.runs.len()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn correctness_workflow_defaults_to_every_path_and_requires_real_chaos_artifact() {
        let args = parse(
            ["--out", "out.json", "--chaos-report", "chaos.json"]
                .map(str::to_owned)
                .into_iter(),
        )
        .unwrap();
        assert_eq!(args.replay_paths, None);
        assert_eq!(args.chaos_report, Some(PathBuf::from("chaos.json")));
        assert!(parse(
            ["--out", "out.json", "--chaos-passed"]
                .map(str::to_owned)
                .into_iter()
        )
        .is_err());
        let capped = parse(
            ["--out", "out.json", "--replay-paths", "10"]
                .map(str::to_owned)
                .into_iter(),
        )
        .unwrap();
        assert_eq!(capped.replay_paths, Some(10));
    }
}
