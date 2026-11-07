//! `crawlx-bench crawl-maze-score`: score a crawl against the
//! security-crawl-maze expected list.
//!
//! ```text
//! crawl-maze-score --run report.json [--prefix /test] [--manifest FILE] [--json]
//! crawl-maze-score --ledger ledger.json [--prefix /g32/test] [--manifest FILE] [--json]
//! ```
//!
//! `--run` takes any JSON artifact of a crawl (a `RunReport`, a page list, a frontier
//! export): every string that is a URL or an absolute path counts as requested. `--ledger`
//! takes the gym's `/__gym/ledger` document and counts its `op` rows. The expected list is
//! the embedded `g32` manifest unless `--manifest` names another fixture manifest.
//! `--prefix` is the path the `.found` endpoints are served under: `/g32/test` for the gym
//! fixture (the default for `--ledger`), `/test` for the upstream blueprint (the default
//! for `--run`). Exit status is 0 when every target was found, 1 otherwise, 2 on usage or
//! input errors.

use crawlx_bench::crawl_maze::{paths_in_json, score, UPSTREAM_PREFIX};
use crawlx_bench::gym::fixtures::crawl_maze::TEST_PREFIX;
use crawlx_bench::gym::manifest::FixtureManifest;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: crawl-maze-score (--run FILE | --ledger FILE) [--prefix PATH] [--manifest FILE] [--json]\n\
  --run FILE       crawl artifact JSON; every URL or absolute path string counts as requested (prefix default /test)\n\
  --ledger FILE    gym ledger JSON (/__gym/ledger); `op` rows count as requested (prefix default /g32/test)\n\
  --prefix PATH    path the .found endpoints are served under\n\
  --manifest FILE  fixture manifest with `expected.crawl_maze` (default: embedded g32)\n\
  --json           print the score as JSON instead of markdown";

struct Args {
    run: Option<PathBuf>,
    ledger: Option<PathBuf>,
    prefix: Option<String>,
    manifest: Option<PathBuf>,
    json: bool,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut args = Args {
        run: None,
        ledger: None,
        prefix: None,
        manifest: None,
        json: false,
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "crawl-maze-score" => {}
            "--run" => args.run = Some(PathBuf::from(it.next().ok_or("--run needs a file")?)),
            "--ledger" => args.ledger = Some(PathBuf::from(it.next().ok_or("--ledger needs a file")?)),
            "--prefix" => args.prefix = Some(it.next().ok_or("--prefix needs a path")?),
            "--manifest" => args.manifest = Some(PathBuf::from(it.next().ok_or("--manifest needs a file")?)),
            "--json" => args.json = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    if args.run.is_some() == args.ledger.is_some() {
        return Err(format!("exactly one of --run or --ledger is required\n{USAGE}"));
    }
    Ok(args)
}

fn read_json(path: &PathBuf) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn run(args: Args) -> Result<ExitCode, String> {
    let manifest = match &args.manifest {
        Some(p) => FixtureManifest::load(p).map_err(|e| format!("manifest {}: {e}", p.display()))?,
        None => FixtureManifest::embedded("g32").map_err(|e| e.to_string())?,
    };
    let targets = &manifest.expected.crawl_maze;
    if targets.is_empty() {
        return Err("manifest has no expected.crawl_maze targets".to_owned());
    }
    let (doc, default_prefix) = match (&args.run, &args.ledger) {
        (Some(p), None) => (read_json(p)?, UPSTREAM_PREFIX),
        (None, Some(p)) => (read_json(p)?, TEST_PREFIX),
        _ => return Err(USAGE.to_owned()),
    };
    let prefix = args.prefix.as_deref().unwrap_or(default_prefix);
    let requested: Vec<String> = if args.ledger.is_some() {
        doc.get("entries")
            .and_then(serde_json::Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter(|r| r.get("kind").and_then(serde_json::Value::as_str) == Some("op"))
                    .filter_map(|r| r.get("path").and_then(serde_json::Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .ok_or("ledger JSON has no `entries` array")?
    } else {
        paths_in_json(&doc).into_iter().collect()
    };
    let s = score(requested.iter().map(String::as_str), targets, prefix);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?);
    } else {
        print!("{}", s.render_markdown());
    }
    Ok(if s.missing.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn main() -> ExitCode {
    match parse(std::env::args().skip(1)).and_then(run) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
    }
}
