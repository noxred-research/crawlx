//! `crawlx-differential`: compare an upstream crawl export with a crawlx run.
//!
//! The crawlx side is either an existing run (`--crawlx FILE` written by a previous
//! `--fixture` run, or `--crawlx-dir DIR` from `crawlx crawl --out DIR`) or produced here by
//! crawling a gym fixture in-process (`--fixture ID`, static plane, no Chromium needed).

use crawlx_bench::differential::{
    CrawlxRun, DifferentialRunner, FixtureRun, Ledger, Thresholds, UpstreamExport,
};
use crawlx_bench::gym::GymServer;
use crawlx_core::config::QueryPolicy;
use crawlx_url::TrailingSlash;
use std::path::PathBuf;
use std::process::ExitCode;
use url::Url;

const USAGE: &str = "usage: crawlx-differential --upstream FILE (--fixture ID | --crawlx FILE | --crawlx-dir DIR) [options]\n\
  --upstream FILE          upstream v2 crawl export (status body with data[] merged, errors body under `errors`)\n\
  --upstream-origin URL    origin upstream crawled (default: origin of the first document)\n\
  --fixture ID              crawl gym fixture ID in-process and compare against it\n\
  --crawlx FILE             crawlx run JSON written by --save-crawlx\n\
  --crawlx-dir DIR          directory written by `crawlx crawl --out DIR` (no frontier: succeeded pages only)\n\
  --crawlx-origin URL       origin crawlx crawled (default: origin of the first page)\n\
  --save-crawlx FILE        with --fixture: write the crawlx run JSON here\n\
  --seed N                  crawl seed for --fixture (default 20261019)\n\
  --query-policy P          keep_all | classify | strip_all for --fixture (default keep_all)\n\
  --request JSON|@FILE      the upstream crawl request (`POST /v2/crawl` body without `url`) the other side received;\n\
                            its limit, includePaths, excludePaths, maxDiscoveryDepth, sitemap, crawlEntireDomain,\n\
                            allowExternalLinks, allowSubdomains and ignoreQueryParameters apply to the --fixture\n\
                            run too (default: none)\n\
  --trailing-slash P        keep | strip | add | manifest: the worker canonicalizer's policy for --fixture (default\n\
                            manifest, `s1`: strip; the compat facade's workers use keep)\n\
  --divergences FILE        ledger (default bench/differential/divergences.toml)\n\
  --markdown-threshold F    per-page similarity (default 0.97)\n\
  --corpus-threshold F      corpus mean similarity (default 0.98)\n\
  --links-threshold F       per-page link Jaccard (default 0.98)\n\
  --label TEXT              scorecard title (default: fixture id or `differential`)\n\
  --out FILE                write the markdown scorecard here (default: stdout)\n\
  --fail-on-warning         exit 3 on warnings\n\
  --strip-tracking          strip tracking parameters from URL keys before comparing admission\n\
                            (default: keep the full query)\n\
  --cardinality-only        compare only the number of attempted URLs, not the sets (a `limit` below the site\n\
                            size: which subset is kept depends on traversal order)\n\
  --host NAME               with --fixture: address the gym by this host name (`gym.test`) instead of its loopback address\n\
  --alias NAME              with --fixture: another host name the fixture's pages link to (repeatable); the worker's\n\
                            resolver maps it and --host to the loopback gym\n\
  --claim-origin            with --fixture: make the fixture own the origin's robots.txt (the gym's claim_origin)\n\
  --seed-path PATH          with --fixture: seed path below the origin instead of the manifest's url_path (`/d2/scope/`)\n\
exit codes: 0 pass (or warnings), 1 undocumented admission difference, 2 usage/input error, 3 warnings with --fail-on-warning";

enum Source {
    Fixture(FixtureRun),
    File(PathBuf),
    Dir(PathBuf),
}

struct Args {
    upstream: PathBuf,
    upstream_origin: Option<Url>,
    source: Source,
    crawlx_origin: Option<Url>,
    save_crawlx: Option<PathBuf>,
    divergences: PathBuf,
    thresholds: Thresholds,
    label: Option<String>,
    out: Option<PathBuf>,
    fail_on_warning: bool,
    strip_tracking: bool,
    cardinality_only: bool,
}

#[allow(clippy::too_many_lines)]
fn parse(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut upstream = None;
    let mut upstream_origin = None;
    let mut fixture: Option<String> = None;
    let mut crawlx_file = None;
    let mut crawlx_dir = None;
    let mut crawlx_origin = None;
    let mut save_crawlx = None;
    let mut strip_tracking = false;
    let mut cardinality_only = false;
    let mut seed = 20_261_019u64;
    let mut query_policy = QueryPolicy::KeepAll;
    let mut request = serde_json::Value::Null;
    let mut trailing_slash = None;
    let mut host = None;
    let mut aliases = Vec::new();
    let mut claim_origin = false;
    let mut seed_path = None;
    let mut divergences = PathBuf::from("bench/differential/divergences.toml");
    let mut thresholds = Thresholds::default();
    let mut label = None;
    let mut out = None;
    let mut fail_on_warning = false;
    let mut it = args;
    let value = |it: &mut dyn Iterator<Item = String>, flag: &str| -> Result<String, String> {
        it.next().ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--upstream" => upstream = Some(PathBuf::from(value(&mut it, "--upstream")?)),
            "--upstream-origin" => {
                let v = value(&mut it, "--upstream-origin")?;
                upstream_origin = Some(Url::parse(&v).map_err(|e| format!("--upstream-origin {v}: {e}"))?);
            }
            "--fixture" => fixture = Some(value(&mut it, "--fixture")?),
            "--crawlx" => crawlx_file = Some(PathBuf::from(value(&mut it, "--crawlx")?)),
            "--crawlx-dir" => crawlx_dir = Some(PathBuf::from(value(&mut it, "--crawlx-dir")?)),
            "--crawlx-origin" => {
                let v = value(&mut it, "--crawlx-origin")?;
                crawlx_origin = Some(Url::parse(&v).map_err(|e| format!("--crawlx-origin {v}: {e}"))?);
            }
            "--save-crawlx" => save_crawlx = Some(PathBuf::from(value(&mut it, "--save-crawlx")?)),
            "--seed" => {
                let v = value(&mut it, "--seed")?;
                seed = v.parse().map_err(|e| format!("--seed {v}: {e}"))?;
            }
            "--query-policy" => {
                query_policy = match value(&mut it, "--query-policy")?.as_str() {
                    "keep_all" => QueryPolicy::KeepAll,
                    "classify" => QueryPolicy::Classify,
                    "strip_all" => QueryPolicy::StripAll,
                    other => {
                        return Err(format!(
                            "--query-policy {other}: expected keep_all, classify or strip_all"
                        ))
                    }
                }
            }
            "--trailing-slash" => {
                trailing_slash = match value(&mut it, "--trailing-slash")?.as_str() {
                    "keep" => Some(TrailingSlash::Keep),
                    "strip" => Some(TrailingSlash::Strip),
                    "add" => Some(TrailingSlash::Add),
                    "manifest" => None,
                    other => {
                        return Err(format!(
                            "--trailing-slash {other}: expected keep, strip, add or manifest"
                        ))
                    }
                }
            }
            "--request" => {
                let v = value(&mut it, "--request")?;
                let text = match v.strip_prefix('@') {
                    Some(file) => {
                        std::fs::read_to_string(file).map_err(|e| format!("--request {file}: {e}"))?
                    }
                    None => v,
                };
                request = serde_json::from_str(&text).map_err(|e| format!("--request: {e}"))?;
                // an export's `crawlxSample.request` is accepted as the request too
                if let Some(inner) = request
                    .get("crawlxSample")
                    .and_then(|s| s.get("request"))
                    .cloned()
                {
                    request = inner;
                }
            }
            "--divergences" => divergences = PathBuf::from(value(&mut it, "--divergences")?),
            "--markdown-threshold" | "--corpus-threshold" | "--links-threshold" => {
                let v = value(&mut it, &a)?;
                let f: f64 = v.parse().map_err(|e| format!("{a} {v}: {e}"))?;
                match a.as_str() {
                    "--markdown-threshold" => thresholds.markdown_page = f,
                    "--corpus-threshold" => thresholds.markdown_corpus = f,
                    _ => thresholds.links = f,
                }
            }
            "--label" => label = Some(value(&mut it, "--label")?),
            "--out" => out = Some(PathBuf::from(value(&mut it, "--out")?)),
            "--fail-on-warning" => fail_on_warning = true,
            "--strip-tracking" => strip_tracking = true,
            "--cardinality-only" => cardinality_only = true,
            "--host" => host = Some(value(&mut it, "--host")?),
            "--alias" => aliases.push(value(&mut it, "--alias")?),
            "--claim-origin" => claim_origin = true,
            "--seed-path" => seed_path = Some(value(&mut it, "--seed-path")?),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    let upstream = upstream.ok_or_else(|| format!("--upstream is required\n{USAGE}"))?;
    let source = match (fixture, crawlx_file, crawlx_dir) {
        (Some(id), None, None) => {
            let mut opts = FixtureRun::new(&id);
            opts.seed = seed;
            opts.query_policy = query_policy;
            opts.request = request;
            opts.trailing_slash = trailing_slash;
            opts.host = host;
            opts.aliases = aliases;
            opts.claim_origin = claim_origin;
            opts.seed_path = seed_path;
            Source::Fixture(opts)
        }
        (None, Some(f), None) => Source::File(f),
        (None, None, Some(d)) => Source::Dir(d),
        _ => {
            return Err(format!(
                "exactly one of --fixture, --crawlx, --crawlx-dir\n{USAGE}"
            ))
        }
    };
    Ok(Args {
        upstream,
        upstream_origin,
        source,
        crawlx_origin,
        save_crawlx,
        divergences,
        thresholds,
        label,
        out,
        fail_on_warning,
        strip_tracking,
        cardinality_only,
    })
}

async fn run(args: Args) -> Result<u8, String> {
    let export =
        UpstreamExport::load(&args.upstream).map_err(|e| format!("{}: {e}", args.upstream.display()))?;
    let ledger =
        Ledger::load(&args.divergences).map_err(|e| format!("{}: {e}", args.divergences.display()))?;
    let upstream_origin = match args.upstream_origin {
        Some(o) => o,
        None => export
            .origin()
            .ok_or("--upstream-origin is required when the export has no documents")?,
    };
    let (run, crawlx_origin, label) = match args.source {
        Source::Fixture(opts) => {
            let gym = GymServer::start("127.0.0.1:0".parse().map_err(|e| format!("bind: {e}"))?)
                .await
                .map_err(|e| e.to_string())?;
            let origin = Url::parse(&opts.crawl_origin(&gym)).map_err(|e| format!("gym origin: {e}"))?;
            let artifacts = std::env::temp_dir().join(format!("crawlx-differential-{}", std::process::id()));
            let run = CrawlxRun::crawl_fixture(&opts, &gym, &artifacts).await;
            gym.shutdown().await;
            let _ = std::fs::remove_dir_all(&artifacts);
            let run = run.map_err(|e| format!("fixture `{}`: {e}", opts.fixture))?;
            if let Some(p) = &args.save_crawlx {
                run.save(p).map_err(|e| format!("{}: {e}", p.display()))?;
            }
            (run, origin, opts.fixture)
        }
        Source::File(p) => {
            let run = CrawlxRun::load(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            let origin = derive_origin(&run, args.crawlx_origin.clone())?;
            (run, origin, "differential".to_owned())
        }
        Source::Dir(d) => {
            let run = CrawlxRun::from_cli_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
            let origin = derive_origin(&run, args.crawlx_origin.clone())?;
            (run, origin, "differential".to_owned())
        }
    };
    let crawlx_origin = args.crawlx_origin.unwrap_or(crawlx_origin);
    let report = DifferentialRunner::new(ledger)
        .with_thresholds(args.thresholds)
        .with_keep_query(!args.strip_tracking)
        .with_cardinality_only(args.cardinality_only)
        .with_label(args.label.unwrap_or(label))
        .compare(&export, &upstream_origin, &run, &crawlx_origin);
    let md = report.to_markdown();
    match &args.out {
        Some(p) => std::fs::write(p, &md).map_err(|e| format!("{}: {e}", p.display()))?,
        None => print!("{md}"),
    }
    eprintln!(
        "crawlx-differential: {:?} ({} findings)",
        report.verdict(),
        report.findings.len()
    );
    Ok(report.exit_code(args.fail_on_warning))
}

fn derive_origin(run: &CrawlxRun, given: Option<Url>) -> Result<Url, String> {
    if let Some(o) = given {
        return Ok(o);
    }
    run.pages
        .iter()
        .find_map(|p| Url::parse(&p.url).ok())
        .and_then(|u| Url::parse(&crawlx_bench::differential::normalize::origin_of(&u)).ok())
        .ok_or_else(|| "--crawlx-origin is required when the run has no pages".to_owned())
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut argv = std::env::args().skip(1).peekable();
    if argv.peek().map(String::as_str) == Some("wire") {
        argv.next();
        return match crawlx_bench::differential::wire::cli::main(argv).await {
            Ok(code) => ExitCode::from(code),
            Err(msg) => {
                eprintln!("{msg}");
                ExitCode::from(2)
            }
        };
    }
    let args = match parse(argv) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    match run(args).await {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("crawlx-differential: {msg}");
            ExitCode::from(2)
        }
    }
}
