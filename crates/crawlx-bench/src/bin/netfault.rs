//! `netfault`: the TCP fault proxy as a standalone tool (`crawlx_bench::netfault`).
//!
//! ```text
//! netfault --listen 127.0.0.1:15432 --upstream db.internal:5432
//!          [--schedule latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,refuse@25s..27s]
//!          [--seed N [--duration 60s] [--faults 6]] [--exit-after-schedule]
//! ```
//!
//! Forwards TCP from `--listen` to `--upstream` and applies a fault schedule whose offsets
//! count from the moment the proxy is listening. `--schedule` is the explicit text spec;
//! `--seed` generates `--faults` non-overlapping faults over `--duration` from the seed alone
//! (the same seed always gives the same schedule; the generated spec is printed on stderr).
//! The two are exclusive; with neither the proxy is a plain forwarder. It runs until SIGINT or
//! SIGTERM, or, with `--exit-after-schedule`, until the schedule is done, and then prints one
//! JSON document on stdout: the schedule, the faults applied and the proxy counters.

use crawlx_bench::netfault::{AppliedFault, FaultSchedule, Proxy, ProxyStats};
use crawlx_bench::soak::parse_duration;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const USAGE: &str = "usage: netfault --listen ADDR --upstream HOST:PORT [options]\n\
  --listen ADDR          address to listen on, e.g. 127.0.0.1:15432\n\
  --upstream HOST:PORT   where to forward\n\
  --schedule SPEC        latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,refuse@25s..27s\n\
  --seed N               generate the schedule from this seed instead\n\
  --duration D           horizon of a generated schedule (default 60s)\n\
  --faults N             faults in a generated schedule (default 6)\n\
  --exit-after-schedule  stop when the schedule is done (default: run until SIGINT/SIGTERM)";

struct Args {
    listen: SocketAddr,
    upstream: String,
    schedule: Option<String>,
    seed: Option<u64>,
    duration: Duration,
    faults: usize,
    exit_after_schedule: bool,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut listen = None;
    let mut upstream = None;
    let mut schedule = None;
    let mut seed = None;
    let mut duration = Duration::from_secs(60);
    let mut faults = 6usize;
    let mut exit_after_schedule = false;
    let value = |it: &mut dyn Iterator<Item = String>, flag: &str| {
        it.next().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => {
                listen = Some(
                    value(&mut it, "--listen")?
                        .parse::<SocketAddr>()
                        .map_err(|e| format!("--listen: {e}"))?,
                );
            }
            "--upstream" => upstream = Some(value(&mut it, "--upstream")?),
            "--schedule" => schedule = Some(value(&mut it, "--schedule")?),
            "--seed" => {
                seed = Some(
                    value(&mut it, "--seed")?
                        .parse::<u64>()
                        .map_err(|e| format!("--seed: {e}"))?,
                );
            }
            "--duration" => duration = parse_duration(&value(&mut it, "--duration")?)?,
            "--faults" => {
                faults = value(&mut it, "--faults")?
                    .parse()
                    .map_err(|e| format!("--faults: {e}"))?;
            }
            "--exit-after-schedule" => exit_after_schedule = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if schedule.is_some() && seed.is_some() {
        return Err(format!("--schedule and --seed are exclusive\n{USAGE}"));
    }
    Ok(Args {
        listen: listen.ok_or_else(|| format!("--listen is required\n{USAGE}"))?,
        upstream: upstream.ok_or_else(|| format!("--upstream is required\n{USAGE}"))?,
        schedule,
        seed,
        duration,
        faults,
        exit_after_schedule,
    })
}

/// Resolve to one socket address.
async fn resolve(upstream: &str) -> Result<SocketAddr, String> {
    tokio::net::lookup_host(upstream)
        .await
        .map_err(|e| format!("--upstream {upstream}: {e}"))?
        .next()
        .ok_or_else(|| format!("--upstream {upstream} does not resolve"))
}

/// Resolves when the process is asked to stop.
async fn stop_signal() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("netfault: SIGTERM handler: {e}");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[derive(serde::Serialize)]
struct Output {
    listen: SocketAddr,
    upstream: SocketAddr,
    schedule: String,
    seed: Option<u64>,
    applied: Vec<AppliedFault>,
    stats: ProxyStats,
}

async fn run(args: Args) -> Result<Output, String> {
    let schedule = match (&args.schedule, args.seed) {
        (Some(spec), _) => FaultSchedule::parse(spec).map_err(|e| format!("--schedule: {e}"))?,
        (None, Some(seed)) => {
            FaultSchedule::generate(seed, args.duration, args.faults).map_err(|e| format!("--seed: {e}"))?
        }
        (None, None) => FaultSchedule::default(),
    };
    let upstream = resolve(&args.upstream).await?;
    let proxy = Proxy::start_on(args.listen, upstream)
        .await
        .map_err(|e| e.chain())?;
    eprintln!("netfault: {} -> {upstream}; schedule `{schedule}`", proxy.addr());
    let cancel = CancellationToken::new();
    let on_signal = cancel.clone();
    tokio::spawn(async move {
        stop_signal().await;
        on_signal.cancel();
    });
    // ends with the last fault, or at once when a signal cancels the schedule
    let applied = proxy.run_schedule(&schedule, cancel.clone()).await;
    if !args.exit_after_schedule {
        // keep forwarding until SIGINT or SIGTERM
        cancel.cancelled().await;
    }
    let stats = proxy.stats();
    proxy.shutdown().await;
    Ok(Output {
        listen: args.listen,
        upstream,
        schedule: schedule.to_string(),
        seed: args.seed,
        applied,
        stats,
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
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("netfault: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match rt.block_on(run(args)) {
        Ok(output) => match serde_json::to_string_pretty(&output) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netfault: serialize: {e}");
                ExitCode::from(2)
            }
        },
        Err(e) => {
            eprintln!("netfault: {e}");
            ExitCode::from(2)
        }
    }
}
