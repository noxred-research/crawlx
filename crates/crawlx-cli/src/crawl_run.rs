//! `crawlx crawl`: seeds, parallel runs, resume, health check, update check and outputs.

use crate::crawl::{CrawlArgs, Resolved, TrailingArg};
use crate::crawl_out::{emit_streams, print_diagnostics, print_summary, seed_dir, write_outputs, SeedRun};
use crate::egress_feed::EgressFeed;
use crate::health;
use crate::input::read_stdin;
use crate::output_args::OutputArgs;
use crate::resume_file::{Outcome, Progress, ResumeFile};
use crate::style::Style;
use crate::update;
use anyhow::{anyhow, bail, Context as _};
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::RunStatus;
use crawlx_core::{CreateCrawl, SystemClock};
use crawlx_extract::secret_validation::SecretValidators;
use crawlx_policy::{AdmissionPolicy, AuthorizationRecord, TenantLimits};
use crawlx_url::TrailingSlash;
use crawlx_worker::surface::resume::{ResumeEntry, ResumeState};
use crawlx_worker::surface::traffic_export::TrafficExportConfig;
use crawlx_worker::{run_local_with, Gates, LocalRun, RunReport, WorkerConfig, WorkerError};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Seeds crawled at the same time when `--parallelism` is not given (the compatibility default).
const DEFAULT_PARALLELISM: usize = 10;

/// Reads one environment variable.
pub(crate) type Getenv<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Run `crawlx crawl` with `getenv` as the environment.
pub(crate) async fn run(
    resolved: Resolved,
    out: &mut dyn Write,
    getenv: Getenv<'_>,
) -> anyhow::Result<ExitCode> {
    let args = &resolved.args;
    let style = Style::detect(args.out.no_color, getenv);

    if args.out.list_output_fields {
        for name in OutputArgs::listed_fields() {
            writeln!(out, "{name}")?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    if args.update {
        let status = update::check(&update::release_url(getenv), env!("CARGO_PKG_VERSION")).await?;
        writeln!(out, "{}", status.message())?;
        return Ok(ExitCode::SUCCESS);
    }
    if args.health_check {
        return health_check(&resolved, out, getenv, style).await;
    }
    if update::auto_check_enabled(getenv, args.disable_update_check) {
        match update::check(&update::release_url(getenv), env!("CARGO_PKG_VERSION")).await {
            Ok(status @ update::UpdateStatus::Available { .. }) => eprintln!("{}", status.message()),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "release check failed"),
        }
    }

    let seeds = resolved.seeds(read_stdin)?;
    let record = args
        .authorization_record
        .as_deref()
        .map(load_record)
        .transpose()?;
    let mut templates = seeds.iter().map(|seed| resolved.template(seed));
    let first = templates
        .next()
        .transpose()?
        .ok_or_else(|| anyhow!("a seed URL or --request is required"))?;
    let output = args.output_dir();
    let mut base = base_config(args, &first, &output, getenv)?;
    base.load_checkpoint_keys_from_lookup(getenv).await?;
    base.load_artifact_custody_from_lookup(getenv).await?;
    // the deployment lists (allowlist bound on record networks, operator blocklist) apply to local runs too
    let egress_feed = EgressFeed::start(getenv).await?;
    let gates_dir = args.gates_dir.as_deref().unwrap_or_else(|| Path::new("gates"));
    let admission = AdmissionPolicy::new(Arc::new(SystemClock))
        .with_gates(load_gates(gates_dir).status())
        .with_egress_lists(egress_feed.lists());
    let mut admitted = Vec::with_capacity(seeds.len());
    for (seed, crawl) in seeds.iter().zip(std::iter::once(Ok(first)).chain(templates)) {
        let mut crawl = crawl?;
        if let Some(r) = &record {
            crawl.safety.authorization_record_ref = Some(r.id);
        }
        let egress = admission
            .admit(&mut crawl, &TenantLimits::default(), record.as_ref())
            .map_err(|errs| {
                anyhow!(
                    "request rejected{}:\n{}",
                    if seeds.len() > 1 {
                        format!(" (seed {seed})")
                    } else {
                        String::new()
                    },
                    errs.iter()
                        .map(|e| format!("  {e}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            })?
            .egress;
        admitted.push((crawl, egress));
    }
    if args.print_config {
        return print_config(&admitted, out);
    }
    let first = admitted
        .first()
        .map(|(c, _)| c)
        .ok_or_else(|| anyhow!("a seed URL or --request is required"))?;

    args.headless.apply_launch(&mut base, getenv)?;
    base.load_article_language_from_lookup(getenv).await?;
    base.load_source_dispatch_from_lookup(getenv)?;
    base.load_delivery_from_lookup(getenv).await?;
    base.traffic_export = TrafficExportConfig::from_env(getenv).context("traffic export")?;
    base.egress.lists = Some(egress_feed.lists());
    base.egress.resolver_https =
        crate::resolver_https_config::from_env(getenv, egress_feed.lists(), CancellationToken::new())?;
    if base.form_ai.is_some() && !first.extract.form_fill.enabled {
        bail!("the --ai-* flags answer form fields: add --automatic-form-fill (or --form-config)");
    }
    std::fs::create_dir_all(&output).with_context(|| format!("creating {}", output.display()))?;
    // parse the output selectors before the crawl so a bad field, template or condition fails fast
    let plan = args.out.plan(
        &output,
        args.compat_defaults && !args.tech_detect,
        first.extract.knowledge_base,
    )?;
    if let (Some(validators), false) = (&base.secret_validators, args.out.silent) {
        if validators.is_empty() {
            writeln!(
                out,
                "secret validation: no validators configured; every finding stays unknown"
            )?;
        }
    }

    // resume: what the previous invocation left for each seed
    let resume_file = args.input.resume.as_deref().map(ResumeFile::load).transpose()?;
    let progress: Vec<Progress> = seeds
        .iter()
        .map(|seed| match &resume_file {
            Some(file) => file.progress(seed, seeds.len()),
            None => Ok(Progress::Fresh),
        })
        .collect::<anyhow::Result<_>>()?;

    // Ctrl-C drains the sessions (graceful checkpoint) and still writes the report
    let cancel = CancellationToken::new();
    let mut watcher = JoinSet::new();
    {
        let cancel = cancel.clone();
        watcher.spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel.cancel();
            }
        });
    }
    let secrets = if admitted.iter().any(|(crawl, _)| crawl.crawl.captcha.is_some()) {
        args.captcha.resolver().await
    } else {
        None
    };
    let mut jobs = Vec::new();
    for (i, ((crawl, egress), progress)) in admitted.iter().zip(&progress).enumerate() {
        let state = match progress {
            Progress::Completed => continue,
            Progress::Fresh => None,
            Progress::Continue(state) => Some(state.clone()),
        };
        let mut cfg = base.clone();
        cfg.egress.extra_allow.clone_from(&egress.extra_allow);
        cfg.egress.extra_ports.clone_from(&egress.extra_ports);
        let mut local = LocalRun::new(crawl.clone(), cfg).with_graceful_drain(cancel.clone());
        if let Some(secrets) = &secrets {
            local = local.with_secrets(Arc::clone(secrets));
        }
        if let Some(r) = &record {
            local = local.with_authorization(r.clone());
        }
        if let Some(state) = state {
            local = local.with_resume(state);
        }
        jobs.push((i, local));
    }
    let parallelism = args.input.parallelism.map_or(DEFAULT_PARALLELISM, usize::from);
    let mut results = run_all(jobs, parallelism).await;
    watcher.abort_all();

    // resume file: written before any output so a failing output step cannot lose it
    let mut outcomes = Vec::with_capacity(seeds.len());
    for (i, seed) in seeds.iter().enumerate() {
        let outcome = match (&progress[i], results.get(&i)) {
            (Progress::Completed, _) => Outcome::Done,
            (_, Some(Ok(report))) => report.resume.clone().map_or(Outcome::Done, Outcome::Stopped),
            (previous, _) => Outcome::Stopped(match previous {
                Progress::Continue(state) => state.clone(),
                _ => ResumeState::new([], [ResumeEntry::new(seed.to_string(), 0)]),
            }),
        };
        outcomes.push((seed.clone(), outcome));
    }
    let stopped = outcomes.iter().any(|(_, o)| matches!(o, Outcome::Stopped(_)));
    if let Some(path) = &args.input.resume {
        ResumeFile::save(path, &outcomes)?;
        if stopped && !args.out.silent {
            writeln!(
                out,
                "resume state written to {}; continue with --resume {}",
                path.display(),
                path.display()
            )?;
        }
    }

    // outputs, seeds in order
    let mut runs = Vec::new();
    let mut failures = Vec::new();
    for (i, seed) in seeds.iter().enumerate() {
        match results.remove(&i) {
            Some(Ok(report)) => runs.push(SeedRun {
                seed: seed.clone(),
                request: admitted[i].0.clone(),
                report,
                dir: seed_dir(&output, seed, seeds.len()),
            }),
            Some(Err(e)) if seeds.len() == 1 => {
                failures.push(format!("crawl failed: {}", crate::authz::chain(&e)));
            }
            Some(Err(e)) => {
                failures.push(format!("seed {seed}: crawl failed: {}", crate::authz::chain(&e)));
            }
            None => {}
        }
    }
    if runs.is_empty() && !failures.is_empty() {
        // nothing finished: there is nothing to write or print
        bail!("{}", failures.join("; "));
    }
    let mut pages_written = Vec::with_capacity(runs.len());
    for run in &runs {
        pages_written.push(write_outputs(&run.dir, &run.request, &run.report)?);
    }
    emit_streams(&plan, &runs, out)?;
    if let Some(path) = &args.out.error_log {
        let all: Vec<_> = runs
            .iter()
            .flat_map(|r| r.report.failures.iter().cloned())
            .collect();
        let written = crawlx_worker::output::write_error_log(path, &all, args.out.no_clobber)
            .map_err(|e| anyhow!("error log: {e}"))?;
        if !args.out.silent {
            writeln!(
                out,
                "error log: {} failure(s) -> {}",
                all.len(),
                written.display()
            )?;
        }
    }
    let mut failed_run = None;
    if !args.out.silent {
        for (run, written) in runs.iter().zip(&pages_written) {
            if seeds.len() > 1 {
                writeln!(out, "seed {}", run.seed)?;
            }
            let mode = run.request.mode;
            if let Err(e) = print_summary(out, style, mode, &run.report, &run.dir, *written) {
                failed_run.get_or_insert(e);
            }
        }
        for (seed, outcome) in &outcomes {
            if matches!(outcome, Outcome::Done) && !runs.iter().any(|r| &r.seed == seed) {
                writeln!(out, "seed {seed}: skipped, completed in the resume file")?;
            }
        }
        if args.headless.enable_diagnostics {
            for run in &runs {
                print_diagnostics(out, &run.report)?;
            }
        }
    } else if let Some(run) = runs.iter().find(|r| r.report.status == RunStatus::Failed) {
        failed_run = Some(anyhow!(
            "run failed ({})",
            run.report.terminal_reason.map_or("none", |t| t.as_str())
        ));
    }
    if let Some(e) = failed_run {
        return Err(e);
    }
    if !failures.is_empty() {
        bail!("{}", failures.join("; "));
    }
    Ok(ExitCode::SUCCESS)
}

/// `--print-config`: the admitted request of every seed as `{seedUrl, configDigest, request}`.
///
/// The request is the redacted form (header and cookie values replaced), and the digest is
/// computed over that same form, so a secret value never influences what is printed. Two runs
/// print the same digest exactly when their effective, admitted requests are equal.
fn print_config<E>(admitted: &[(CreateCrawl, E)], out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let mut entries = Vec::with_capacity(admitted.len());
    for (crawl, _) in admitted {
        let redacted = crawl.redacted();
        entries.push(serde_json::json!({
            "seedUrl": redacted.seed_url,
            "configDigest": redacted.digest()?.to_string(),
            "request": redacted,
        }));
    }
    serde_json::to_writer_pretty(&mut *out, &entries)?;
    writeln!(out)?;
    Ok(ExitCode::SUCCESS)
}

/// The worker configuration every seed of the crawl shares (launch flags and traffic export
/// are applied by the caller).
pub(crate) fn base_config(
    args: &CrawlArgs,
    crawl: &CreateCrawl,
    output: &Path,
    getenv: Getenv<'_>,
) -> anyhow::Result<WorkerConfig> {
    let gates_dir = args.gates_dir.clone().unwrap_or_else(|| PathBuf::from("gates"));
    let database_url = crate::config_check::database_url(args.database_url.as_deref())?;
    let mut cfg = WorkerConfig {
        store: crate::config_check::store_config(database_url.as_deref())?,
        database_url,
        artifacts_dir: output.join("artifacts"),
        artifact_spool: crate::config_check::artifact_spool_from_env(getenv)?,
        retained_profiles: crawlx_worker::RetainedProfilePolicy::from_env(getenv)?,
        request_identity_key: WorkerConfig::request_identity_key_from_lookup(getenv)?,
        gates: load_gates(&gates_dir),
        ..WorkerConfig::default()
    };
    cfg.egress.proxy_routes = args.proxy_routes.routes(getenv)?;
    cfg.launch.launch_profile = crawl.dynamic.launch_profile;
    (cfg.model, cfg.planner) = args.model.settings(crawl.dynamic.system1_mode)?;
    if let Some(t) = args.trailing_slash {
        cfg.trailing_slash = match t {
            TrailingArg::Keep => TrailingSlash::Keep,
            TrailingArg::Strip => TrailingSlash::Strip,
            TrailingArg::Add => TrailingSlash::Add,
        };
    }
    cfg.form_ai = args.ai.settings()?;
    if args.kb_validate_secrets {
        let validators = match &args.secret_validators {
            Some(path) => SecretValidators::load(path)
                .with_context(|| format!("--secret-validators {}", path.display()))?,
            None => SecretValidators::builtin(),
        };
        cfg.secret_validators = Some(Arc::new(validators));
    }
    Ok(cfg)
}

/// Run the jobs, at most `parallelism` at a time, in submission order. Results are keyed by
/// the job's seed index.
async fn run_all(
    jobs: Vec<(usize, LocalRun)>,
    parallelism: usize,
) -> BTreeMap<usize, Result<RunReport, WorkerError>> {
    let permits = Arc::new(Semaphore::new(parallelism.max(1)));
    let mut set = JoinSet::new();
    let mut index_of = BTreeMap::new();
    for (index, local) in jobs {
        let permits = Arc::clone(&permits);
        let handle = set.spawn(async move {
            // the semaphore lives as long as this task and is never closed
            let _permit = permits.acquire_owned().await;
            run_local_with(local).await
        });
        index_of.insert(handle.id(), index);
    }
    let mut results = BTreeMap::new();
    while let Some(joined) = set.join_next_with_id().await {
        match joined {
            Ok((id, result)) => {
                if let Some(index) = index_of.remove(&id) {
                    results.insert(index, result);
                }
            }
            Err(e) => {
                if let Some(index) = index_of.remove(&e.id()) {
                    results.insert(
                        index,
                        Err(WorkerError::Config(format!(
                            "the crawl task ended abnormally: {e}"
                        ))),
                    );
                }
            }
        }
    }
    results
}

/// `--health-check`: print the table, exit 1 when a check fails.
async fn health_check(
    resolved: &Resolved,
    out: &mut dyn Write,
    getenv: Getenv<'_>,
    style: Style,
) -> anyhow::Result<ExitCode> {
    let args = &resolved.args;
    let input = &args.input;
    let wants_seeds = !(input.targets.is_empty()
        && input.url.is_empty()
        && input.list.is_empty()
        && args.request.is_none());
    let mut seed_error = None;
    let seeds = if wants_seeds {
        resolved.seeds(read_stdin).unwrap_or_else(|e| {
            seed_error = Some(format!("{e:#}"));
            Vec::new()
        })
    } else {
        Vec::new()
    };
    let (crawl, mut admission) = match seeds.first().map(|s| resolved.template(s)) {
        Some(Ok(crawl)) => (Some(crawl), Ok(())),
        Some(Err(e)) => (None, Err(format!("{e:#}"))),
        None => (None, seed_error.map_or(Ok(()), Err)),
    };
    let mut crawl = crawl;
    if let Some(c) = crawl.as_mut() {
        let record = match args.authorization_record.as_deref().map(load_record).transpose() {
            Ok(r) => r,
            Err(e) => {
                admission = Err(format!("{e:#}"));
                None
            }
        };
        if admission.is_ok() {
            if let Some(r) = &record {
                c.safety.authorization_record_ref = Some(r.id);
            }
            admission = match EgressFeed::start(getenv).await {
                Ok(feed) => AdmissionPolicy::new(Arc::new(SystemClock))
                    .with_gates(
                        load_gates(args.gates_dir.as_deref().unwrap_or_else(|| Path::new("gates"))).status(),
                    )
                    .with_egress_lists(feed.lists())
                    .admit(c, &TenantLimits::default(), record.as_ref())
                    .map(|_| ())
                    .map_err(|errs| {
                        errs.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("; ")
                    }),
                Err(e) => Err(format!("{e:#}")),
            };
        }
    }
    let placeholder;
    let for_config = match &crawl {
        Some(c) => c,
        None => {
            placeholder =
                CreateCrawl::new(Url::parse("https://health-check.invalid/").map_err(|e| anyhow!("{e}"))?);
            &placeholder
        }
    };
    let mut config_error = None;
    let mut cfg = match base_config(args, for_config, &args.output_dir(), getenv) {
        Ok(cfg) => cfg,
        Err(e) => {
            config_error = Some(format!("{e:#}"));
            WorkerConfig::default()
        }
    };
    let launch_error = args
        .headless
        .apply_launch(&mut cfg, getenv)
        .err()
        .map(|e| format!("{e:#}"));
    if admission.is_ok() {
        if let Some(e) = config_error {
            admission = Err(e);
        }
    }
    let rows = health::checks(&health::Subject {
        cfg: &cfg,
        crawl: crawl.as_ref(),
        seeds: &seeds,
        admission,
        launch_error,
        needs_browser: crawl.as_ref().is_none_or(|c| c.mode != CrawlMode::Static),
    })
    .await;
    let passed = health::print(&rows, out, style)?;
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

pub(crate) fn load_record(path: &Path) -> anyhow::Result<AuthorizationRecord> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing authorization record {}", path.display()))
}

/// Load `gates/*.passed`; an absent gate is logged, the worker refuses what needs it.
pub(crate) fn load_gates(dir: &Path) -> Gates {
    let gates = Gates::load(dir);
    for (gate, why) in gates.problems() {
        tracing::debug!(gate = gate.as_str(), reason = %why, "milestone gate not attested");
    }
    gates
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use clap::Parser as _;

    #[test]
    fn local_config_receives_deployment_proxy_routes_without_changing_request_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("crawlx.toml");
        std::fs::write(
            &file,
            "[fetch]\nbasic_proxy_url = 'http://file-user:file-secret@basic.test:8080'\n\
             enhanced_proxy_url = 'https://file-user:file-secret@enhanced.test'\n",
        )
        .unwrap();
        let cli = crate::Cli::try_parse_from([
            "crawlx",
            "crawl",
            "https://target.test",
            "--fetch-enhanced-proxy-url",
            "socks5h://flag-user:flag-secret@enhanced-flag.test:1080",
        ])
        .unwrap();
        let crate::Command::Crawl(args) = cli.command else {
            panic!("expected crawl")
        };
        let getenv = |key: &str| match key {
            crate::config_check::CONFIG_ENV => Some(file.display().to_string()),
            crate::config_check::BASIC_PROXY_URL_ENV => {
                Some("http://env-user:env-secret@basic-env.test:8080".to_owned())
            }
            _ => None,
        };
        let mut crawl = CreateCrawl::new(Url::parse("https://target.test").unwrap());
        crawl.fetch.proxy = Some(Url::parse("http://request.test:3128").unwrap());
        let cfg = base_config(&args, &crawl, dir.path(), &getenv).unwrap();
        let routes = cfg.egress.proxy_routes;
        assert_eq!(routes.basic.as_ref().unwrap().host_str(), Some("basic-env.test"));
        assert_eq!(routes.basic.unwrap().password(), Some("env-secret"));
        assert_eq!(
            routes.enhanced.as_ref().unwrap().host_str(),
            Some("enhanced-flag.test")
        );
        assert_eq!(routes.enhanced.unwrap().password(), Some("flag-secret"));
        assert_eq!(crawl.fetch.proxy.unwrap().host_str(), Some("request.test"));
    }
}
