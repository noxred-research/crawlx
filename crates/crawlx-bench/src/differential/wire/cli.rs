//! The `crawlx-differential wire ...` subcommands: capture a wire family against a running API
//! and compare two captures.

use super::driver::{run_family, Target};
use super::sink::Sink;
use super::{compare, Hooks, ShellHooks, WireCapture, WireSpec};
use crate::differential::Ledger;
use std::path::PathBuf;
use std::sync::Arc;

/// Usage text of the `wire` subcommands.
pub const USAGE: &str = "usage: crawlx-differential wire capture --spec FILE --family ID --api URL --origin URL --out FILE [options]\n\
       crawlx-differential wire compare --firecrawl FILE --crawlx FILE [options]\n\
capture options:\n\
  --spec FILE          scenario file (bench/differential/wire-scenarios.json)\n\
  --family ID          the family of the spec to run\n\
  --api URL            API root the requests go to (http://127.0.0.1:3102; for the facade .../compat/firecrawl)\n\
  --origin URL         origin the system reaches the gym on (http://gym.test:4101): `{seed}` expands to it plus the family's seed path\n\
  --bearer TOKEN       bearer token (default fc-self-host)\n\
  --system NAME        firecrawl (default) or crawlx\n\
  --provenance P       black_box_run (default) or crawlx_facade\n\
  --commit SHA         pinned upstream commit, recorded verbatim\n\
  --gym-ledger URL     the gym's /__gym/ledger as this runner reaches it (quiet check, access log)\n\
  --sink-bind ADDR     start the webhook sink here (default 0.0.0.0:0)\n\
  --sink-origin URL    origin the system reaches the sink on; `{port}` expands to the sink's port (http://gym.test:{port})\n\
  --restart-cmd CMD    shell command that restarts the API and its workers (scenarios with a hook)\n\
  --out FILE           capture file to write\n\
compare options:\n\
  --firecrawl FILE     capture of the real Firecrawl\n\
  --crawlx FILE        capture of the crawlx facade\n\
  --divergences FILE   ledger (default bench/differential/divergences.toml)\n\
  --label ID           family id (default: the capture's family)\n\
  --out FILE           scorecard (default: stdout)\n\
  --fail-on-warning    exit 3 on warnings\n\
exit codes: 0 pass (or warnings), 1 undocumented behavior difference, 2 usage/input error, 3 warnings with --fail-on-warning";

fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value"))
}

async fn capture(args: impl Iterator<Item = String>) -> Result<u8, String> {
    let mut it = args;
    let (mut spec, mut family, mut api, mut origin, mut out) = (None, None, None, None, None);
    let mut bearer = "fc-self-host".to_owned();
    let mut system = "firecrawl".to_owned();
    let mut provenance = "black_box_run".to_owned();
    let (mut commit, mut gym_ledger, mut sink_origin, mut restart) = (None, None, None, None);
    let mut sink_bind = "0.0.0.0:0".to_owned();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--spec" => spec = Some(PathBuf::from(value(&mut it, &a)?)),
            "--family" => family = Some(value(&mut it, &a)?),
            "--api" => api = Some(value(&mut it, &a)?),
            "--origin" => origin = Some(value(&mut it, &a)?),
            "--out" => out = Some(PathBuf::from(value(&mut it, &a)?)),
            "--bearer" => bearer = value(&mut it, &a)?,
            "--system" => system = value(&mut it, &a)?,
            "--provenance" => provenance = value(&mut it, &a)?,
            "--commit" => commit = Some(value(&mut it, &a)?),
            "--gym-ledger" => gym_ledger = Some(value(&mut it, &a)?),
            "--sink-bind" => sink_bind = value(&mut it, &a)?,
            "--sink-origin" => sink_origin = Some(value(&mut it, &a)?),
            "--restart-cmd" => restart = Some(value(&mut it, &a)?),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    let need = |v: Option<String>, flag: &str| v.ok_or_else(|| format!("{flag} is required\n{USAGE}"));
    let spec_path = spec.ok_or_else(|| format!("--spec is required\n{USAGE}"))?;
    let out = out.ok_or_else(|| format!("--out is required\n{USAGE}"))?;
    let (family_id, api, origin) = (
        need(family, "--family")?,
        need(api, "--api")?,
        need(origin, "--origin")?,
    );
    let spec = WireSpec::load(&spec_path).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let family = spec
        .family(&family_id)
        .ok_or_else(|| format!("unknown family `{family_id}`"))?;
    let needs_sink = family.scenarios.iter().any(|s| s.webhook.is_some());
    let (sink, sink_origin) = match (needs_sink, sink_origin) {
        (true, Some(o)) => {
            let sink = Sink::start(
                sink_bind
                    .parse()
                    .map_err(|e| format!("--sink-bind {sink_bind}: {e}"))?,
            )
            .await
            .map_err(|e| e.to_string())?;
            let o = o.replace("{port}", &sink.port.to_string());
            (Some(Arc::new(sink)), Some(o))
        }
        (true, None) => return Err("the family has webhook scenarios: --sink-origin is required".to_owned()),
        (false, _) => (None, None),
    };
    let hooks: Option<Arc<dyn Hooks>> =
        restart.map(|restart| Arc::new(ShellHooks { restart }) as Arc<dyn Hooks>);
    let mut target = Target::new(&system, &provenance, &api, &bearer, &origin).with_commit(commit);
    if let Some(url) = gym_ledger {
        target = target.with_gym_ledger(&url);
    }
    if let (Some(sink), Some(origin)) = (sink, sink_origin) {
        target = target.with_sink(sink, &origin);
    }
    if let Some(hooks) = hooks {
        target = target.with_hooks(hooks);
    }
    let cap = run_family(&target, family).await.map_err(|e| e.to_string())?;
    cap.save(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    eprintln!(
        "crawlx-differential wire: {} captured {} scenarios of `{}` into {}",
        target.system,
        cap.scenarios.len(),
        cap.family,
        out.display()
    );
    Ok(0)
}

fn compare_cmd(args: impl Iterator<Item = String>) -> Result<u8, String> {
    let mut it = args;
    let (mut firecrawl, mut crawlx, mut label, mut out) = (None, None, None, None);
    let mut divergences = PathBuf::from("bench/differential/divergences.toml");
    let mut fail_on_warning = false;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--firecrawl" => firecrawl = Some(PathBuf::from(value(&mut it, &a)?)),
            "--crawlx" => crawlx = Some(PathBuf::from(value(&mut it, &a)?)),
            "--divergences" => divergences = PathBuf::from(value(&mut it, &a)?),
            "--label" => label = Some(value(&mut it, &a)?),
            "--out" => out = Some(PathBuf::from(value(&mut it, &a)?)),
            "--fail-on-warning" => fail_on_warning = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    let firecrawl = firecrawl.ok_or_else(|| format!("--firecrawl is required\n{USAGE}"))?;
    let crawlx = crawlx.ok_or_else(|| format!("--crawlx is required\n{USAGE}"))?;
    let fc = WireCapture::load(&firecrawl).map_err(|e| format!("{}: {e}", firecrawl.display()))?;
    let cx = WireCapture::load(&crawlx).map_err(|e| format!("{}: {e}", crawlx.display()))?;
    let ledger = Ledger::load(&divergences).map_err(|e| format!("{}: {e}", divergences.display()))?;
    let label = label.unwrap_or_else(|| fc.family.clone());
    let report = compare::compare(&label, &fc, &cx, &ledger)?;
    let md = report.to_markdown();
    match &out {
        Some(p) => std::fs::write(p, &md).map_err(|e| format!("{}: {e}", p.display()))?,
        None => print!("{md}"),
    }
    eprintln!(
        "crawlx-differential wire: {:?} ({} findings)",
        report.verdict(),
        report.findings.len()
    );
    Ok(report.exit_code(fail_on_warning))
}

/// Entry point of `crawlx-differential wire <capture|compare> ...`; `args` are the arguments
/// after `wire`. Returns the process exit code.
///
/// # Errors
/// A message for usage and input errors (exit code 2).
pub async fn main(args: impl Iterator<Item = String>) -> Result<u8, String> {
    let mut it = args;
    match it.next().as_deref() {
        Some("capture") => capture(it).await,
        Some("compare") => compare_cmd(it),
        Some("-h" | "--help") | None => Err(USAGE.to_owned()),
        Some(other) => Err(format!("unknown wire command `{other}`\n{USAGE}")),
    }
}
