//! `crawl-bench`: crawl coverage and throughput of the crawlx URL plane per target and crawl
//! profile, with baseline comparison (equivalent of a reference crawl-bench tool). The metrics,
//! profiles and baseline rules are documented in `crawlx_bench::crawl_bench`.

use clap::Parser;
use crawlx_bench::crawl_bench::{
    browser_available, compare, run, BenchConfig, Metric, Profile, Report, Target, DEFAULT_SEED,
};
use crawlx_bench::error::chain;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const LONG_ABOUT: &str = "\
Crawl each target under each crawl profile, repeat N times, and report per-target and
aggregate metrics: pages fetched, pages/second, browser interactions, distinct endpoints
discovered, recall against the target's known endpoint list (gym fixtures that ship one),
requests/second, wall time and the p50/p95 latency of served pages. Every target sits behind a
recording reverse proxy, so what the target received (requests, 5xx answers, latency) is
measured server-side; the crawl itself runs through the real worker
(crawlx_worker::run_local_with). Repeats are combined by the per-field median; latency
percentiles are taken over all requests of all repeats.

TARGETS
  gym:<fixture>   a CrawlerGym fixture served by an in-process gym (gym:s1, gym:g32,
                  gym:hybrid-mix carry a known endpoint list; every fixture can be crawled)
  http(s)://...   an application you run (DVWA, Juice Shop, a staging site). The proxy forwards
                  to it without the crawl egress policy: name only targets you may test.

PROFILES
  static           the gym reference slice (mode=static): crawlx defaults at the gym's pace (50 ms/origin)
  crawlx-defaults  the request defaults of `crawlx crawl`, production politeness (250 ms/origin)
  compat-flag-defaults  the compatibility flag dialect's defaults: host scope rdn, depth 3, depth-first, no JS endpoints,
                   no known files or sitemap, robots.txt not obeyed, 4 MiB bodies, 150 req/s
  hybrid           the static request plus the browser plane (mode=hybrid, page hooks, 40 interactions)
  browser-only     the browser plane alone (mode=dynamic, same budget)
  hybrid and browser-only need a Chromium executable (CRAWLX_CHROMIUM_PATH); without one they are
  skipped with a message on stderr (exit status 2 when no runnable profile is left).
  pps is pages/second and interactions the browser interactions attempted. After the table a
  second table lists every profile's pps relative to static on the same target (`2.00x` = twice
  the pages per second); the ratio is reported, never gated.

OUTPUT
  A table on stdout (one row per target and profile, then the aggregate rows `(all)`), progress
  lines on stderr. --json FILE writes the report: results by target and profile, the aggregate
  by profile and the discovered endpoint lists.

BASELINES
  --baseline FILE compares against a report written by an earlier --json: every cell shows its
  change. With --max-regress PCT the exit status is 1 when a gated metric got worse by more
  than PCT percent. Higher is better for pages, endpoints, recall, rps, pps; lower is better for
  errors, seconds, p50_ms, p95_ms. requests and interactions are informational. Only targets and profiles present
  in both files are compared; the (all) rows only when both files cover the same targets.
  Timing metrics are noisy across machines: narrow the gate with
  --gate-metrics pages,endpoints,recall to the deterministic coverage numbers.
  bench/baselines/crawl-bench.json is a recorded report of gym:s1, gym:g32 and gym:hybrid-mix.

EXIT STATUS
  0 success, 1 regression beyond --max-regress, 2 usage or runtime error.

EXAMPLES
  crawl-bench --target gym:s1 --target gym:g32 --profile static --profile compat-flag-defaults
  crawl-bench --target gym:s1 --repeat 5 --json new.json --baseline old.json --max-regress 10
  crawl-bench --target gym:s1 --target gym:g32 --target gym:hybrid-mix --profile static \\
      --baseline bench/baselines/crawl-bench.json --max-regress 0 --gate-metrics pages,endpoints,recall
  crawl-bench --target http://127.0.0.1:4280/ --profile compat-flag-defaults --duration-seconds 600";

#[derive(Parser, Debug)]
#[command(name = "crawl-bench", version, about = "Crawl coverage and throughput benchmark of the crawlx URL plane", long_about = LONG_ABOUT)]
struct Cli {
    /// Target to crawl: gym:<fixture> or an http(s) URL; repeat for several targets.
    #[arg(long = "target", value_name = "TARGET", required = true, value_parser = parse_target)]
    targets: Vec<Target>,

    /// Crawl profile: static, compat-flag-defaults, crawlx-defaults, hybrid or browser-only
    /// (the last two need Chromium and are skipped without it); repeat for several profiles.
    #[arg(long = "profile", value_name = "PROFILE", default_value = "static", value_parser = parse_profile)]
    profiles: Vec<Profile>,

    /// Crawls per target and profile; the median is reported.
    #[arg(long, value_name = "N", default_value_t = 3)]
    repeat: u32,

    /// Seed of every crawl and of the gym.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_SEED)]
    seed: u64,

    /// Wall-clock budget of one crawl.
    #[arg(long, value_name = "SECONDS", default_value_t = 120)]
    duration_seconds: u32,

    /// URL budget of one crawl.
    #[arg(long, value_name = "N", default_value_t = 10_000)]
    max_pages: u32,

    /// Write the report as JSON.
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,

    /// Report written by an earlier --json to compare against.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Exit with status 1 when a gated metric is worse than the baseline by more than this
    /// percentage.
    #[arg(long, value_name = "PCT", requires = "baseline")]
    max_regress: Option<f64>,

    /// Metrics --max-regress gates on (default: every metric with a better/worse direction).
    #[arg(long, value_name = "METRICS", value_delimiter = ',', requires = "max_regress", value_parser = parse_metric)]
    gate_metrics: Vec<Metric>,
}

fn parse_target(spec: &str) -> Result<Target, String> {
    Target::parse(spec).map_err(|e| e.to_string())
}

fn parse_profile(name: &str) -> Result<Profile, String> {
    Profile::parse(name).map_err(|e| e.to_string())
}

fn parse_metric(name: &str) -> Result<Metric, String> {
    Metric::parse(name).map_err(|e| e.to_string())
}

fn read_baseline(path: &Path) -> Result<Report, String> {
    let json = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Report::from_json(&json).map_err(|e| format!("baseline {}: {}", path.display(), chain(&e)))
}

fn write_report(path: &Path, report: &Report) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let json = report.to_json().map_err(|e| chain(&e))?;
    std::fs::write(path, json).map_err(|e| format!("write {}: {e}", path.display()))
}

async fn execute(cli: Cli) -> Result<ExitCode, String> {
    // Read the baseline first so a bad path fails before minutes of crawling.
    let baseline = cli.baseline.as_deref().map(read_baseline).transpose()?;

    let (runnable, skipped): (Vec<Profile>, Vec<Profile>) = cli
        .profiles
        .into_iter()
        .partition(|p| !p.needs_browser() || browser_available());
    for profile in &skipped {
        eprintln!("crawl-bench: skipping profile {profile}: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
    }
    if runnable.is_empty() {
        return Err(
            "every requested profile needs Chromium and none was found (set CRAWLX_CHROMIUM_PATH)".to_owned(),
        );
    }
    let mut cfg = BenchConfig::new(cli.targets);
    cfg.profiles = runnable;
    cfg.repeat = cli.repeat;
    cfg.seed = cli.seed;
    cfg.duration_seconds = cli.duration_seconds;
    cfg.max_pages = cli.max_pages;

    let report = run(&cfg, |p| {
        eprintln!("{}/{} #{}/{}: {}", p.target, p.profile, p.run, p.of, p.metrics);
    })
    .await
    .map_err(|e| chain(&e))?;

    if let Some(path) = &cli.json {
        write_report(path, &report)?;
        eprintln!("crawl-bench: wrote {}", path.display());
    }
    print!("{}", report.table(baseline.as_ref()));
    let ratios = report.ratio_table();
    if !ratios.is_empty() {
        print!("\npage throughput relative to static\n{ratios}");
    }

    if let (Some(base), Some(pct)) = (&baseline, cli.max_regress) {
        let gate = if cli.gate_metrics.is_empty() {
            Metric::gated()
        } else {
            cli.gate_metrics
        };
        let regressions = compare(&report, base, pct, &gate).map_err(|e| chain(&e))?;
        for r in &regressions {
            eprintln!("crawl-bench: regression: {r}");
        }
        if !regressions.is_empty() {
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("crawl-bench: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(execute(cli)) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("crawl-bench: {message}");
            ExitCode::from(2)
        }
    }
}
