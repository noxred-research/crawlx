//! `gym-server --bind 127.0.0.1:0 [--seed N] [--claim-origin ID]`: serve the CrawlerGym fixtures until Ctrl-C.

use crawlx_bench::gym::fixtures;
use crawlx_bench::gym::GymServer;
use std::net::SocketAddr;
use std::process::ExitCode;

const USAGE: &str = "usage: gym-server [--bind ADDR] [--seed N] [--claim-origin ID] [--list]\n\
  --bind ADDR        listen address (default 127.0.0.1:0, a free port)\n\
  --seed N           seed all fixture pages are rendered with (default 0)\n\
  --claim-origin ID  fixture whose robots.txt the origin serves (default s1; g32 and d2 have their own)\n\
  --list             print the fixture ids and exit";

struct Args {
    bind: SocketAddr,
    seed: u64,
    claim_origin: Option<String>,
    list: bool,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut out = Args {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        seed: 0,
        claim_origin: None,
        list: false,
    };
    let mut it = args;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--bind" => {
                let v = it.next().ok_or("--bind needs a value")?;
                out.bind = v.parse().map_err(|e| format!("--bind {v}: {e}"))?;
            }
            "--seed" => {
                let v = it.next().ok_or("--seed needs a value")?;
                out.seed = v.parse().map_err(|e| format!("--seed {v}: {e}"))?;
            }
            "--claim-origin" => {
                let v = it.next().ok_or("--claim-origin needs a value")?;
                if fixtures::find(&v).is_none() {
                    return Err(format!(
                        "--claim-origin {v}: not an embedded fixture (see --list)"
                    ));
                }
                out.claim_origin = Some(v);
            }
            "--list" => out.list = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    if args.list {
        for def in fixtures::all() {
            println!("{}", def.id);
        }
        return ExitCode::SUCCESS;
    }
    let handle = match GymServer::start(args.bind).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("gym-server: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(id) = &args.claim_origin {
        handle.claim_origin(id);
    }
    handle.reset(args.seed);
    println!("{}", handle.base_url);
    eprintln!(
        "gym-server: serving {} fixtures at {} (seed {}); Ctrl-C to stop",
        fixtures::all().len(),
        handle.base_url,
        args.seed
    );
    if let Err(e) = tokio::signal::ctrl_c().await {
        eprintln!("gym-server: cannot wait for Ctrl-C: {e}");
        return ExitCode::FAILURE;
    }
    handle.shutdown().await;
    ExitCode::SUCCESS
}
