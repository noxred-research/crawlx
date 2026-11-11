//! `replay`, `export`, `serve`, `worker`, `migrate`.

use crate::inspect::{connect, parse_run};
use crate::model_args::ModelArgs;
use crate::ocr_args::OcrArgs;
use crate::pprof::{PprofArgs, PprofListener};
use anyhow::{anyhow, bail, Context as _};
use clap::{Args, ValueEnum};
use crawlx_api::{ApiConfig, ApiKeyBootstrap};
use crawlx_core::config::System1Mode;
use crawlx_core::repo::{ArtifactStore, PageRecord};
use crawlx_core::{CrawlRunId, TransitionId};
use crawlx_storage::InspectRepo;
use crawlx_worker::{
    Exporter, Field, OutputFilters, ReplayMode, ReplayPlan, ReplayRunner, RunReport, StoreFields, Stores,
    Template, WorkerConfig,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// `--mode` of `replay`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ReplayModeArg {
    /// Compare each step's resulting state with the recorded one.
    #[value(name = "verify")]
    Verify,
    /// Execute only.
    #[value(name = "reproduce")]
    Reproduce,
}

/// Arguments of `crawlx replay`.
#[derive(Args, Debug)]
pub struct ReplayArgs {
    /// Recorded run id.
    pub run_id: String,
    /// Target transition id (`crawlx inspect transitions`).
    #[arg(long, value_name = "TRANSITION_ID")]
    pub to: String,
    #[arg(long, value_enum, default_value = "verify")]
    /// Mode.
    pub mode: ReplayModeArg,
    #[arg(long, env = "CRAWLX_DATABASE_URL", hide_env_values = true)]
    /// Database url.
    pub database_url: Option<String>,
    /// Scratch directory for replay artifacts.
    #[arg(long, default_value = "./crawlx-out/replay", value_name = "DIR")]
    pub artifacts_dir: PathBuf,
}

/// `--format` of `export`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// One request/response record per page (compatibility `-jsonl`).
    #[value(name = "jsonl")]
    Jsonl,
    /// One line per field or template value.
    #[value(name = "text")]
    Text,
    /// The full run: `run`, `session`, `page`, `state`, `action` and `coverage` records
    /// (database runs only).
    #[value(name = "dump")]
    Dump,
}

/// Arguments of `crawlx export`.
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Run id, or the `report.json` (or its directory) written by `crawlx crawl --output`.
    pub run_id: String,
    /// Output format.
    #[arg(long, value_enum, default_value = "jsonl")]
    pub format: ExportFormat,
    /// Fields for text output (comma separated): url, path, fqdn, rdn, rurl, qurl, qpath, file,
    /// ufile, key, value, kv, dir, udir or a custom field name.
    #[arg(
        long,
        value_name = "FIELDS",
        value_delimiter = ',',
        conflicts_with = "output_template"
    )]
    pub field: Vec<String>,
    /// Template for text output, e.g. `{{email}} - {{url}}`.
    #[arg(long, value_name = "TEMPLATE")]
    pub output_template: Option<String>,
    /// Keep only lines whose URL or value matches one of these regexes.
    #[arg(long, value_name = "REGEX")]
    pub match_regex: Vec<String>,
    /// Drop lines whose URL or value matches one of these regexes.
    #[arg(long, value_name = "REGEX")]
    pub filter_regex: Vec<String>,
    /// Keep only URLs with one of these path extensions.
    #[arg(long, value_name = "EXT", value_delimiter = ',')]
    pub extension_match: Vec<String>,
    /// Drop URLs with one of these path extensions.
    #[arg(long, value_name = "EXT", value_delimiter = ',')]
    pub extension_filter: Vec<String>,
    /// Append field values to per-host wordlists `DIR/{scheme}_{host}_{field}.txt`.
    #[arg(long, visible_alias = "store-field-dir", value_name = "DIR")]
    pub store_fields: Option<PathBuf>,
    /// Store only these fields (comma separated, repeatable), independently of display fields.
    /// Without `--store-fields`, use `field_wordlists` beside `--out`, the report, or in `crawlx-out`.
    #[arg(long, value_name = "FIELDS", value_delimiter = ',')]
    pub store_field: Vec<String>,
    /// JSONL record fields to drop (e.g. `timestamp,headers`).
    #[arg(long, value_name = "NAME", value_delimiter = ',')]
    pub exclude_fields: Vec<String>,
    /// Include the stored HTML body in JSONL records.
    #[arg(long)]
    pub include_body: bool,
    /// Output file; standard output when omitted.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    #[arg(long, env = "CRAWLX_DATABASE_URL", hide_env_values = true)]
    /// Database url.
    pub database_url: Option<String>,
    /// Artifacts dir (`./crawlx-artifacts`, or `<output>/artifacts` next to a `report.json`).
    #[arg(long, value_name = "DIR")]
    pub artifacts_dir: Option<PathBuf>,
}

/// Arguments of `crawlx serve`.
#[derive(Args, Debug)]
pub struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:8080")]
    /// Bind.
    pub bind: SocketAddr,
    #[arg(long, env = "CRAWLX_DATABASE_URL", hide_env_values = true)]
    /// Database url.
    pub database_url: Option<String>,
    /// Non-owner database role used only by authenticated API requests (PostgreSQL only; MariaDB has none yet, SQLite refuses it).
    #[arg(long, env = "CRAWLX_API_DATABASE_URL", hide_env_values = true)]
    pub api_database_url: Option<String>,
    /// Development only: allow requests to use the database owner role.
    #[arg(long, env = "CRAWLX_ALLOW_OWNER_API")]
    pub allow_owner_api: bool,
    #[arg(long, default_value = "./crawlx-artifacts", value_name = "DIR")]
    /// Artifacts dir.
    pub artifacts_dir: PathBuf,
    /// Bootstrap API key as `tenant=cx_live_<26 characters from a-z and 2-7>`, or
    /// `tenant=fc-<16 to 64 ASCII letters or digits>` with `--compat-keys`. Repeatable.
    #[arg(long = "api-key", value_name = "TENANT=KEY")]
    pub api_keys: Vec<String>,
    /// Accept prefixed `fc-...` bearer keys on the `/compat` routes
    /// (`compat.prefixedKeys`; the environment variable `CRAWLX_COMPAT_KEYS=1` does the
    /// same); an `fc-` key never opens a native `/v1` route.
    #[arg(long)]
    pub compat_keys: bool,
    /// Compatibility defaults: strict or native_defaults; an explicit flag wins over the environment.
    #[arg(long, env = "CRAWLX_COMPAT_MODE", value_parser = parse_compat_mode)]
    pub compat_mode: Option<crawlx_api::CompatMode>,
    /// Requests per minute per tenant (all of its keys share one bucket). Default 6000; 0 disables limiting.
    #[arg(long)]
    pub rate_limit_per_minute: Option<u32>,
    #[arg(long, env = "CRAWLX_WEBHOOK_SECRET", hide_env_values = true)]
    /// Webhook secret.
    pub webhook_secret: Option<String>,
    /// Unauthenticated `GET /metrics` listener for a scraper sidecar; loopback addresses only.
    #[arg(long, env = "CRAWLX_METRICS_BIND")]
    pub metrics_bind: Option<SocketAddr>,
    /// The unauthenticated pprof debug listener.
    #[command(flatten)]
    pub pprof: PprofArgs,
    /// OCR for `/parse` uploads (scanned PDF pages, images).
    #[command(flatten)]
    pub ocr: OcrArgs,
}

/// Arguments of `crawlx worker`.
#[derive(Args, Debug)]
pub struct WorkerArgs {
    #[arg(long, env = "CRAWLX_DATABASE_URL", hide_env_values = true)]
    /// Database url.
    pub database_url: Option<String>,
    #[arg(long, default_value = "./crawlx-artifacts", value_name = "DIR")]
    /// Artifacts dir.
    pub artifacts_dir: PathBuf,
    /// Reap expired leases, resume recovering sessions (restore + reconcile) and exit when idle.
    #[arg(long)]
    pub recover: bool,
    #[arg(long, default_value_t = 4)]
    /// Max sessions.
    pub max_sessions: usize,
    #[arg(long, default_value_t = 4)]
    /// Contexts per browser.
    pub contexts_per_browser: usize,
    /// System 1 model and LLM planner endpoints.
    #[command(flatten)]
    pub model: ModelArgs,
    /// Deployment-owned basic and enhanced proxy routes.
    #[command(flatten)]
    pub proxy_routes: crate::config_check::ProxyArgs,
    /// Unauthenticated `GET /metrics` listener for a scraper sidecar; loopback addresses only.
    #[arg(long, env = "CRAWLX_METRICS_BIND")]
    pub metrics_bind: Option<SocketAddr>,
    /// The unauthenticated pprof debug listener.
    #[command(flatten)]
    pub pprof: PprofArgs,
    /// OCR for scanned PDF pages and images.
    #[command(flatten)]
    pub ocr: OcrArgs,
    /// Directory of the milestone gate files (`g1.passed`, `g3.passed`).
    #[arg(long, env = "CRAWLX_GATES_DIR", default_value = "gates", value_name = "DIR")]
    pub gates_dir: PathBuf,
    /// Attach to a running Chrome over its DevTools websocket instead of launching one
    /// (`ws://127.0.0.1:9222/devtools/browser/…`); admitted only for `test_environment` and
    /// `authorized_security_test` runs.
    #[arg(long, value_name = "URL")]
    pub cdp_ws_url: Option<url::Url>,
    /// Reuse the attached browser's default context instead of incognito contexts.
    #[arg(long, requires = "cdp_ws_url")]
    pub no_incognito: bool,
    /// Retired plaintext profile root. Supplying it returns an explicit migration error.
    #[arg(long, env = "CRAWLX_PROFILES_DIR", value_name = "DIR")]
    pub profiles_dir: Option<PathBuf>,
    /// Download the pinned Chromium (SHA-256 verified) when none is installed. Off by default;
    /// `crawlx browser install` does it ahead of time.
    #[arg(long, env = "CRAWLX_AUTO_DOWNLOAD_CHROMIUM")]
    pub auto_download_chromium: bool,
    /// Where downloaded Chromium builds live (default `.cache/chromium`).
    #[arg(long, env = "CRAWLX_CHROMIUM_CACHE", value_name = "DIR")]
    pub chromium_cache: Option<PathBuf>,
}

/// Arguments of `crawlx migrate`.
#[derive(Args, Debug)]
pub struct MigrateArgs {
    #[arg(long, env = "CRAWLX_DATABASE_URL", hide_env_values = true)]
    /// Database url.
    pub database_url: Option<String>,
}

pub(crate) async fn migrate(args: MigrateArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    // `migrate` is the one command that may create a SQLite database file
    let database =
        crate::inspect::connect_database(args.database_url.as_deref(), crate::inspect::Open::Migrate).await?;
    database
        .migrate()
        .await
        .map_err(|e| anyhow!("migration failed: {}", crate::authz::chain(&e)))?;
    writeln!(out, "migrations applied")?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn worker(
    args: WorkerArgs,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<ExitCode> {
    if args.profiles_dir.is_some() {
        bail!(
            "--profiles-dir plaintext reuse is retired; configure encrypted retained profiles through CRAWLX_PROFILE_KEY_REF"
        );
    }
    let Some(url) = crate::config_check::database_url(args.database_url.as_deref())? else {
        bail!(
            "`worker` leases work from the database: pass --database-url, set CRAWLX_DATABASE_URL or CRAWLX_DATABASE_URL_FILE"
        );
    };
    // one live set of deployment lists for every run this worker leases; files reload on SIGHUP and a poll
    let egress_feed = crate::egress_feed::EgressFeed::start(getenv).await?;
    let proxy_routes = args.proxy_routes.routes(getenv)?;
    let (model, planner) = args
        .model
        .settings(args.model.system1_mode.map_or(System1Mode::Off, Into::into))?;
    // Self-host provider variables (`CRAWLX_LLM_BASE_URL`, `CRAWLX_LLM_MODEL`, `CRAWLX_LLM_API_KEY`,
    // `EXTRACTION_PROVIDER_*`, `BRANDING_LLM_*`) feed the document LLM behind the scrape formats
    // `json`, `summary`, `question`, `highlights`, `query` and the `branding` refinement
    let intel = crawlx_api::config::IntelConfig::default()
        .from_env()
        .map_err(|e| anyhow!("LLM settings: {e}"))?;
    let llms = crawlx_api::intel::worker_llm(&intel).map_err(|e| anyhow!("LLM settings: {e}"))?;
    // OCR for scanned PDFs and images; `off` (the default) leaves the `ocr_unavailable` warnings
    let ocr = args.ocr.engine(getenv).await?;
    if let Some(ocr) = &ocr {
        tracing::info!(backend = ocr.backend().name(), "OCR enabled for scrape runs");
    }
    let mut cfg = WorkerConfig {
        store: crate::config_check::store_config(Some(&url))?,
        database_url: Some(url),
        request_identity_key: WorkerConfig::request_identity_key_from_lookup(getenv)?,
        model,
        planner,
        artifacts_dir: args.artifacts_dir,
        artifact_spool: crate::config_check::artifact_spool_from_env(getenv)?,
        max_sessions: args.max_sessions,
        contexts_per_browser: args.contexts_per_browser,
        idle_exit_after: args.recover.then_some(Duration::from_secs(75)),
        gates: crate::crawl_run::load_gates(&args.gates_dir),
        cdp_ws_url: args.cdp_ws_url,
        incognito: !args.no_incognito,
        retained_profiles: crawlx_worker::RetainedProfilePolicy::from_env(getenv)?,
        auto_download_chromium: args.auto_download_chromium,
        chromium_cache: args
            .chromium_cache
            .unwrap_or_else(crawlx_browser::install::default_cache_root),
        llm: llms.llm,
        extraction_llm: llms.extraction,
        branding_llm: llms.branding,
        ocr,
        traffic_export: crawlx_worker::surface::traffic_export::TrafficExportConfig::from_env(getenv)
            .context("traffic export")?,
        egress: crawlx_worker::EgressConfig {
            lists: Some(egress_feed.lists()),
            proxy_routes,
            resolver_https: crate::resolver_https_config::from_env(
                getenv,
                egress_feed.lists(),
                CancellationToken::new(),
            )?,
            ..crawlx_worker::EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    cfg.load_checkpoint_keys_from_lookup(getenv).await?;
    cfg.load_artifact_custody_from_lookup(getenv).await?;
    cfg.load_article_language_from_lookup(getenv).await?;
    cfg.load_source_dispatch_from_lookup(getenv)?;
    cfg.load_delivery_from_lookup(getenv).await?;
    // Bind before the worker starts so a bad address fails fast; the listener drains once the
    // worker returns (it already handles SIGINT/SIGTERM itself).
    let metrics_stop = CancellationToken::new();
    let metrics = match args.metrics_bind {
        Some(bind) => {
            let listener = crawlx_api::metrics::bind_metrics(bind)
                .await
                .map_err(|e| anyhow!("metrics listener failed: {e}"))?;
            Some(tokio::spawn(crawlx_api::metrics::serve_metrics_on(
                listener,
                metrics_stop.clone(),
            )))
        }
        None => None,
    };
    // same fail-fast bind as the metrics listener; it drains once the worker returns
    let pprof = PprofListener::start(&args.pprof).await?;
    let worked = crawlx_worker::run(cfg).await;
    metrics_stop.cancel();
    if let Some(task) = metrics {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "metrics listener failed"),
            Err(e) => tracing::warn!(error = %e, "metrics listener task ended abnormally"),
        }
    }
    if let Some(pprof) = pprof {
        pprof.shutdown().await;
    }
    egress_feed.stop().await;
    worked.map_err(|e| anyhow!("worker failed: {}", crate::authz::chain(&e)))?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn serve(args: ServeArgs) -> anyhow::Result<ExitCode> {
    let database_url = crate::config_check::database_url(args.database_url.as_deref())?;
    let mut cfg = ApiConfig {
        bind: args.bind,
        store: crate::config_check::store_config(database_url.as_deref())?,
        database_url,
        api_database_url: args.api_database_url,
        allow_owner_api: args.allow_owner_api,
        artifacts_dir: args.artifacts_dir,
        artifact_spool: crate::config_check::artifact_spool_from_env(&|name| std::env::var(name).ok())?,
        metrics_bind: args.metrics_bind,
        compat_mode_override: args.compat_mode,
        ..ApiConfig::default()
    };
    if cfg.database_url.is_none() {
        tracing::warn!(
            "in-memory API mode: crawls stay queued, no separate worker can execute them, and runs are lost on exit; configure a database (--database-url) for API/worker runs, or use `crawlx crawl` locally"
        );
    }
    for spec in &args.api_keys {
        let (tenant, key) = spec
            .split_once('=')
            .filter(|(t, k)| !t.is_empty() && !k.is_empty())
            .ok_or_else(|| anyhow!("--api-key expects TENANT=KEY"))?;
        cfg.api_keys.push(ApiKeyBootstrap::new(tenant, key));
    }
    if let Some(n) = args.rate_limit_per_minute {
        cfg.rate_limit_per_minute = n;
    }
    cfg.compat.prefixed_keys = args.compat_keys;
    if let Some(s) = crate::config_check::webhook_secret(args.webhook_secret.as_deref())? {
        cfg.webhook_secret = s;
    }
    cfg.ocr = args.ocr.config(&|k| std::env::var(k).ok())?;
    let getenv = |k: &str| std::env::var(k).ok();
    // the deployment lists reach every run's egress policy and the admission of `POST /v1/crawls`;
    // the operator keys verify `operator_signature` ownership proofs of authorization records
    let egress_feed = crate::egress_feed::EgressFeed::start(&getenv).await?;
    cfg.egress_lists = Some(egress_feed.lists());
    cfg.operator_keys = crate::config_check::operator_keys(&getenv)?;
    let pprof = PprofListener::start(&args.pprof).await?;
    let served = crawlx_api::run(cfg).await;
    if let Some(pprof) = pprof {
        pprof.shutdown().await;
    }
    egress_feed.stop().await;
    served.map_err(|e| anyhow!("api failed: {}", crate::authz::chain(&e)))?;
    Ok(ExitCode::SUCCESS)
}

fn parse_compat_mode(value: &str) -> Result<crawlx_api::CompatMode, String> {
    crawlx_api::CompatMode::parse(value).ok_or_else(|| "expected strict or native_defaults".to_owned())
}

#[cfg(test)]
mod compat_mode_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use clap::Parser;

    #[test]
    fn serve_accepts_both_modes_and_rejects_unknown_modes() {
        for (value, mode) in [
            ("strict", crawlx_api::CompatMode::Strict),
            ("native_defaults", crawlx_api::CompatMode::NativeDefaults),
            ("native-defaults", crawlx_api::CompatMode::NativeDefaults),
        ] {
            let cli = crate::Cli::try_parse_from(["crawlx", "serve", "--compat-mode", value]).unwrap();
            let crate::Command::Serve(args) = cli.command else {
                panic!("expected serve");
            };
            assert_eq!(args.compat_mode, Some(mode));
        }
        assert!(crate::Cli::try_parse_from(["crawlx", "serve", "--compat-mode", "unknown"]).is_err());
    }
}

/// Where `crawlx export` reads pages from.
enum ExportSource {
    /// A run in the database.
    Database(CrawlRunId),
    /// A `report.json` written by `crawlx crawl --output`.
    Report(PathBuf),
}

/// The part of `report.json` export reads.
#[derive(serde::Deserialize)]
struct LocalReport {
    pages: Vec<PageRecord>,
}

fn export_source(run_id: &str) -> anyhow::Result<ExportSource> {
    if let Ok(run) = parse_run(run_id) {
        return Ok(ExportSource::Database(run));
    }
    let path = Path::new(run_id);
    let report = if path.is_dir() {
        path.join("report.json")
    } else {
        path.to_path_buf()
    };
    if report.is_file() {
        Ok(ExportSource::Report(report))
    } else {
        bail!("{run_id:?} is neither a run id nor a report.json path")
    }
}

fn build_exporter(args: &ExportArgs, output_dir: &Path) -> anyhow::Result<Exporter> {
    let format = match args.format {
        ExportFormat::Jsonl | ExportFormat::Dump => crawlx_worker::ExportFormat::Jsonl,
        ExportFormat::Text => crawlx_worker::ExportFormat::Text,
    };
    let fields = if args.field.is_empty() {
        Vec::new()
    } else {
        Field::parse_list(&args.field.join(",")).map_err(|e| anyhow!("--field: {e}"))?
    };
    let stored_field_selection = if args.store_field.is_empty() {
        None
    } else {
        Some(Field::parse_list(&args.store_field.join(",")).map_err(|e| anyhow!("--store-field: {e}"))?)
    };
    let template = args
        .output_template
        .as_deref()
        .map(|t| Template::parse(t).with_context(|| format!("--output-template {t:?}")))
        .transpose()?;
    let filters = OutputFilters::new(
        &args.match_regex,
        &args.filter_regex,
        &args.extension_match,
        &args.extension_filter,
    )
    .context("--match-regex/--filter-regex")?;
    let store_fields = args
        .store_fields
        .clone()
        .or_else(|| {
            stored_field_selection
                .as_ref()
                .map(|_| output_dir.join(crawlx_worker::output::store_fields::DEFAULT_DIR))
        })
        .map(StoreFields::new);
    Ok(Exporter {
        format,
        fields,
        template,
        filters,
        store_fields,
        stored_field_selection,
        exclude_fields: args.exclude_fields.clone(),
        include_body: args.include_body,
        ..Exporter::default()
    })
}

/// Load the HTML artifact of every page that has one, keyed by URL.
async fn load_bodies(artifacts: &dyn ArtifactStore, pages: &[PageRecord]) -> BTreeMap<String, String> {
    let mut bodies = BTreeMap::new();
    for p in pages {
        let Some(r) = &p.html else { continue };
        match artifacts.get(r).await {
            Ok(bytes) => {
                bodies.insert(
                    p.url.url.to_string(),
                    String::from_utf8_lossy(&bytes).into_owned(),
                );
            }
            Err(e) => tracing::warn!(error = %e, artifact = %r.id, "html artifact unavailable"),
        }
    }
    bodies
}

/// The full dump: one typed record per run, session, page, state, action, ledger row.
fn dump(report: &RunReport, w: &mut dyn Write) -> anyhow::Result<u64> {
    let mut lines = 0u64;
    let mut emit = |kind: &str, value: serde_json::Value| -> anyhow::Result<()> {
        let mut obj = serde_json::json!({ "type": kind });
        if let (Some(o), Some(v)) = (obj.as_object_mut(), value.as_object()) {
            o.extend(v.clone());
        } else if let Some(o) = obj.as_object_mut() {
            o.insert("value".to_owned(), value);
        }
        writeln!(w, "{obj}")?;
        lines = lines.saturating_add(1);
        Ok(())
    };
    emit(
        "run",
        serde_json::json!({
            "run_id": report.run_id,
            "status": report.status,
            "terminal_reason": report.terminal_reason,
            "counters": report.counters,
        }),
    )?;
    for s in &report.sessions {
        emit("session", serde_json::to_value(s)?)?;
    }
    for p in &report.pages {
        emit("page", serde_json::to_value(p)?)?;
    }
    for s in &report.states {
        emit("state", serde_json::to_value(s)?)?;
    }
    for a in &report.actions {
        emit("action", serde_json::to_value(a)?)?;
    }
    for l in &report.ledger {
        emit("coverage", serde_json::to_value(l)?)?;
    }
    Ok(lines)
}

pub(crate) async fn export(args: ExportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let source = export_source(&args.run_id)?;
    let output_dir = args
        .out
        .as_deref()
        .and_then(Path::parent)
        .or_else(|| match &source {
            ExportSource::Report(path) => path.parent(),
            ExportSource::Database(_) => None,
        })
        .unwrap_or_else(|| Path::new("./crawlx-out"));
    let exporter = build_exporter(&args, output_dir)?;
    let artifacts_dir = match (&args.artifacts_dir, &source) {
        (Some(d), _) => d.clone(),
        (None, ExportSource::Report(p)) => p
            .parent()
            .map(|d| d.join("artifacts"))
            .unwrap_or_else(|| PathBuf::from("artifacts")),
        (None, ExportSource::Database(_)) => PathBuf::from("./crawlx-artifacts"),
    };
    let database_url = match &source {
        ExportSource::Database(_) => Some(args.database_url.clone().ok_or_else(|| {
            anyhow!("export reads the database: pass --database-url or set CRAWLX_DATABASE_URL")
        })?),
        ExportSource::Report(_) => {
            if args.format == ExportFormat::Dump {
                bail!("--format dump needs a run id and a database");
            }
            None
        }
    };
    let mut cfg = WorkerConfig {
        database_url,
        request_identity_key: WorkerConfig::request_identity_key_from_lookup(&|key| std::env::var(key).ok())?,
        artifacts_dir,
        ..WorkerConfig::default()
    };
    // Reports decrypt sealed artifacts through the catalog; they never publish.
    cfg.artifact_keys = crawlx_worker::config::artifact_keys_from_lookup(&|key| std::env::var(key).ok())
        .await
        .map_err(|e| anyhow!("{}", crate::authz::chain(&e)))?;
    let stores = Stores::open_read_only(&cfg).await.map_err(|e| anyhow!("{e}"))?;
    let (report, mut pages) = match &source {
        ExportSource::Database(run) => {
            let report = crawlx_worker::run::build_report(&stores, *run)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            let pages = report.pages.clone();
            (Some(report), pages)
        }
        ExportSource::Report(path) => {
            let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            let local: LocalReport =
                serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
            (None, local.pages)
        }
    };
    pages.sort_by(|a, b| a.url.url.as_str().cmp(b.url.url.as_str()));
    let bodies = if args.include_body && args.format != ExportFormat::Dump {
        load_bodies(stores.artifacts.as_ref(), &pages).await
    } else {
        BTreeMap::new()
    };

    let mut file = match &args.out {
        Some(path) => Some(std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => None,
    };
    let lines = {
        let w: &mut dyn Write = match file.as_mut() {
            Some(f) => f,
            None => out,
        };
        match (args.format, &report) {
            (ExportFormat::Dump, Some(report)) => dump(report, w)?,
            (ExportFormat::Dump, None) => bail!("--format dump needs a run id and a database"),
            _ => {
                exporter
                    .export_pages(&pages, |p| bodies.get(p.url.url.as_str()).cloned(), w)?
                    .lines
            }
        }
    };
    if let (Some(mut f), Some(path)) = (file, &args.out) {
        f.flush()?;
        writeln!(out, "exported {lines} lines to {}", path.display())?;
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn replay(
    args: ReplayArgs,
    out: &mut dyn Write,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<ExitCode> {
    let run = parse_run(&args.run_id)?;
    let transition: TransitionId = args
        .to
        .parse()
        .map_err(|e| anyhow!("{:?} is not a transition id: {e}", args.to))?;
    let mut cfg = WorkerConfig {
        database_url: args.database_url.clone(),
        request_identity_key: WorkerConfig::request_identity_key_from_lookup(getenv)?,
        artifacts_dir: args.artifacts_dir.clone(),
        ..WorkerConfig::default()
    };
    cfg.load_checkpoint_keys_from_lookup(getenv).await?;
    cfg.load_artifact_custody_from_lookup(getenv).await?;
    let store = connect(args.database_url.as_deref()).await?;
    let action = crawlx_worker::on_store!(&store, pg => InspectRepo::new(pg.clone()).transition_action(run, transition)
        .await)
        .context("reading transitions")?
        .ok_or_else(|| anyhow!("transition {transition} is not part of run {run}"))?;
    let stores = Stores::open(&cfg).await.map_err(|e| anyhow!("{e}"))?;
    let plan = ReplayPlan::load(&stores, run, action)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let mode = match args.mode {
        ReplayModeArg::Verify => ReplayMode::Verify,
        ReplayModeArg::Reproduce => ReplayMode::Reproduce,
    };
    let report = ReplayRunner::run(cfg, plan, mode, None, None)
        .await
        .map_err(|e| anyhow!("replay failed: {e}"))?;
    for s in &report.steps {
        writeln!(out, "{}", serde_json::to_string(s)?)?;
    }
    writeln!(
        out,
        "replay {} steps={} ok={}",
        if report.verify { "verify" } else { "reproduce" },
        report.steps.len(),
        report.ok
    )?;
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}
