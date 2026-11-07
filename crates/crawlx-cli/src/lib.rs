//! The `crawlx` command line.
//!
//! `crawl` admits a request through `crawlx_policy::AdmissionPolicy`, runs it in-process with
//! `crawlx_worker::run_local` and writes `pages/*.md`, `metadata.json`, `links.json` and
//! `report.json`; `inspect`, `replay` and `export` read a PostgreSQL store; `serve`, `worker`
//! and `migrate` start the API, the worker process and apply migrations.
//!
//! `serve` and `worker` accept `--pprof-bind ADDR` (env `CRAWLX_PPROF_BIND`), katana's
//! `-pprof-server` counterpart ([`pprof`]): an **unauthenticated** listener with
//! `GET /debug/pprof/profile?seconds=N` (CPU profile in pprof `profile.proto` form) and
//! `GET /debug/pprof/heap` (JSON memory summary). It is refused on non-loopback addresses unless
//! `CRAWLX_PPROF_ALLOW_NON_LOOPBACK=1` (`--pprof-allow-non-loopback`) is set. `crawl` runs in
//! the foreground and has no such listener.

#![warn(missing_docs)]

pub mod admin;
pub mod admin_ops;
mod ai_args;
pub mod archive;
mod archive_replay;
mod authz;
mod browser_cmd;
pub mod captcha_args;
pub mod config_check;
mod config_file;
mod config_intel;
pub mod crawl;
mod crawl_out;
mod crawl_run;
mod duration;
mod egress_feed;
mod extract;
mod extraction_import;
mod headless_args;
mod health;
mod healthcheck;
mod input;
mod inspect;
mod katana_args;
mod katana_defaults;
mod mcp;
mod merge;
pub mod migration_inspect;
mod model_args;
mod ocr_args;
mod ops;
mod output_args;
pub mod pprof;
pub mod profiles;
pub mod protocol;
pub mod response_replay;
mod resume_file;
mod style;
pub mod tls_args;
mod update;

use clap::{Parser, Subcommand};
use std::io::Write;
use std::process::ExitCode;

pub use admin::{AdminArgs, AdminCommand, AuditExportArgs};
pub use admin_ops::OpsCommand;
pub use ai_args::AiArgs;
pub use authz::{AuthzArgs, AuthzCommand};
pub use config_check::{ConfigArgs, ConfigCheckArgs, ConfigCommand, CrawlxConfig};
pub use crawl::{
    CrawlArgs, FieldScopeArg, LaunchArg, ModeArg, PageTypeArg, ProfileArg, StrategyArg, TrailingArg,
};
pub use extract::ExtractArgs;
pub use headless_args::HeadlessArgs;
pub use healthcheck::HealthcheckArgs;
pub use input::InputArgs;
pub use inspect::{InspectArgs, InspectKind};
pub use katana_args::normalize_args;
pub use mcp::McpArgs;
pub use model_args::{ModelArgs, System1ModeArg};
pub use ocr_args::OcrArgs;
pub use ops::{ExportArgs, ExportFormat, MigrateArgs, ReplayArgs, ReplayModeArg, ServeArgs, WorkerArgs};
pub use output_args::OutputArgs;
pub use pprof::PprofArgs;
pub use update::{UpdateStatus, DEFAULT_RELEASE_URL, RELEASE_URL_ENV, UPDATE_CHECK_ENV};

/// `crawlx`.
#[derive(Parser, Debug)]
#[command(
    name = "crawlx",
    version,
    about = "crawlx: crawl a site with a static plane, a browser plane, or both",
    long_about = "crawlx crawls websites. `crawl` runs a crawl in-process; `serve` starts the REST API; \
                  `worker` runs a lease-loop worker against PostgreSQL; `inspect`, `replay` and `export` \
                  read a stored run; `migrate` applies the database migrations."
)]
pub struct Cli {
    /// Log filter (`RUST_LOG` syntax); default `warn`. `crawl -v` logs `info`, `crawl --debug`
    /// (or `DEBUG=true`) logs `debug`, `crawl --silent` logs errors only; this flag wins.
    #[arg(long, global = true, env = "CRAWLX_LOG")]
    pub log: Option<String>,
    /// OTLP collector endpoint (`http://host:4317`) for traces and metrics. Only active in a
    /// build with the `otlp` feature of `crawlx-telemetry`; otherwise a warning is logged.
    #[arg(long, global = true, env = "CRAWLX_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,
    #[command(subcommand)]
    /// Command.
    pub command: Command,
}

/// Subcommands.
///
/// Large crawl and worker argument sets are boxed to keep command values compact without
/// changing their Clap subcommands or flags.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Crawl URLs in-process and write pages, metadata, links and a report.
    ///
    /// Seeds are the positional URLs, `-u` lists, `--list` files, or standard input with `-`;
    /// every seed is a separate run with its own frontier, at most `-p` at a time, and their
    /// outputs are printed in seed order. `--config FILE` supplies flags (katana-style YAML) or a
    /// request body (JSON, or TOML table `[crawl]`); flags override the file.
    ///
    /// Operator environment: `CRAWLX_TRAFFIC_ENDPOINT` and `CRAWLX_TRAFFIC_TOKEN` post every
    /// fetch-plane exchange to a collector as batched JSON (`CRAWLX_TRAFFIC_ATTRIBUTES` adds
    /// static attributes, `CRAWLX_TRAFFIC_ALLOW_INSECURE=1` allows plain http to a non-loopback
    /// collector, `CRAWLX_TRAFFIC_INCLUDE_CREDENTIALS=1` keeps credential headers);
    /// `CRAWLX_UPDATE_CHECK=1` asks `CRAWLX_RELEASE_URL` once at start for a newer release;
    /// `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1` permits `--no-sandbox`; `DEBUG=true` logs at debug
    /// level and prints the full error chain with a backtrace. The deployment lists apply to
    /// every run: `egress.deployment_allowlist` and `egress.operator_blocklist` of `crawlx.toml`
    /// (`CRAWLX_CONFIG`), or the files named by `CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE` and
    /// `CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE` (a file replaces the static list); `SIGHUP`
    /// re-reads the files.
    Crawl(Box<CrawlArgs>),
    /// Print a stored run: run, pages, states, epochs, actions, transitions, coverage, traffic.
    Inspect(InspectArgs),
    /// Re-execute a recorded transition path against the live target through a session.
    Replay(ReplayArgs),
    /// Export a stored run as JSON lines.
    Export(ExportArgs),
    /// Extract article content from local HTML without network access.
    Extract(ExtractArgs),
    /// Export, inspect, or import a bounded local WARC/WACZ archive.
    Archive(archive::ArchiveArgs),
    /// Inspect or convert a declarative upstream manifest without running source-language code.
    SourceImport(migration_inspect::SourceImportArgs),
    /// Manage operator-approved encrypted browser profiles under an active session lease.
    Profiles(profiles::ProfilesArgs),
    /// Extract an operator-authorized local corpus without enabling file URLs on the API.
    Corpus(protocol::CorpusArgs),
    /// Acquire through an explicitly registered operator protocol adapter.
    Protocol(protocol::ProtocolArgs),
    /// Replay an approved retained response without a target network request.
    ReplayResponse(response_replay::ReplayResponseArgs),
    /// Start the REST/SSE API. The deployment lists (`egress.deployment_allowlist`,
    /// `egress.operator_blocklist`, or the `CRAWLX_EGRESS_*_FILE` files, re-read on `SIGHUP` and
    /// every 60 s) bound every run; `CRAWLX_AUTHZ_OPERATOR_KEYS_FILE` holds the operator keys that
    /// verify `operator_signature` authorization records.
    Serve(ServeArgs),
    /// Run a worker: lease sessions and URL batches from PostgreSQL. The deployment lists of
    /// `serve` apply to every run it leases.
    Worker(Box<WorkerArgs>),
    /// Apply the database migrations.
    Migrate(MigrateArgs),
    /// Operator commands: pause, resume, cancel, drain, freeze, reconcile,
    /// verify-artifacts, sweep-retention, durability-audit, safety-audit, engine, workers,
    /// status, audit-export.
    Admin(AdminArgs),
    /// Configuration: `config check` validates `crawlx.toml` + `CRAWLX_*` and prints the
    /// effective values with secrets redacted.
    Config(ConfigArgs),
    /// Run a Model Context Protocol server over stdio (Firecrawl MCP tools backed by a crawlx API).
    Mcp(mcp::McpArgs),
    /// Probe a URL and exit 0 for a 2xx answer, 1 otherwise: the container `HEALTHCHECK` of the
    /// distroless API image and of the worker (`docker/docker-compose.yml`).
    Healthcheck(healthcheck::HealthcheckArgs),
    /// Browser tooling: `browser install` downloads the pinned Chromium (SHA-256 verified) into
    /// the cache, ahead of `--auto-download-chromium`.
    Browser(browser_cmd::BrowserArgs),
    /// Authorization records: `create`, `show`, `revoke` and `verify` call a crawlx
    /// API; `sign` and `challenge` work offline.
    Authz(AuthzArgs),
}

/// Run the command, writing results to `out`. Returns the process exit code.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub async fn execute(cli: Cli, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    config_check::validate_operator_environment(&|name| std::env::var_os(name))?;
    execute_with_env(cli, out, &|key| std::env::var(key).ok()).await
}

/// `DEBUG=true` (katana's switch): debug logging, and `main` prints the full error chain with a
/// backtrace.
#[must_use]
pub fn debug_enabled(getenv: &dyn Fn(&str) -> Option<String>) -> bool {
    getenv("DEBUG").is_some_and(|v| v.trim() == "true")
}

/// The log filter: `--log`/`CRAWLX_LOG` when given, else what the verbosity flags ask for,
/// else `warn`.
fn log_filter(explicit: Option<&str>, from_flags: Option<&'static str>) -> String {
    explicit
        .map(str::to_owned)
        .or_else(|| from_flags.map(str::to_owned))
        .unwrap_or_else(|| "warn".to_owned())
}

/// [`execute`] reading the environment (`CRAWLX_UPDATE_CHECK`, `CRAWLX_TRAFFIC_*`,
/// `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI`, `DEBUG`, `NO_COLOR`, ...) through `getenv`, so callers
/// and tests need not touch the process environment.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub async fn execute_with_env(
    cli: Cli,
    out: &mut dyn Write,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<ExitCode> {
    let Cli {
        log,
        otlp_endpoint,
        command,
    } = cli;
    let env_debug = debug_enabled(getenv);
    let init = |from_flags: Option<&'static str>| {
        init_logging(&log_filter(log.as_deref(), from_flags), otlp_endpoint.as_deref())
    };
    // the guard lives for the whole command so OTLP export flushes at exit
    let default_logs = || init(env_debug.then_some("debug"));
    match command {
        Command::Crawl(args) => {
            // the flags of a `--config` file can ask for verbose logging: resolve them first
            let resolved = crawl::Resolved::new(*args)?;
            let _telemetry = init(resolved.args.out.log_filter(env_debug));
            Box::pin(crawl_run::run(resolved, out, getenv)).await
        }
        Command::Inspect(args) => {
            let _telemetry = default_logs();
            inspect::run(args, out).await
        }
        Command::Replay(args) => {
            let _telemetry = default_logs();
            Box::pin(ops::replay(args, out, getenv)).await
        }
        Command::Export(args) => {
            let _telemetry = default_logs();
            ops::export(args, out).await
        }
        Command::Extract(args) => extract::run(args, out).await,
        Command::Archive(args) => archive::execute(args, out).await,
        Command::SourceImport(args) => migration_inspect::run(args, out).await,
        Command::Profiles(args) => profiles::run(args).await,
        Command::Corpus(args) => protocol::run(args, out).await,
        Command::Protocol(args) => protocol::acquire(args, out).await,
        Command::ReplayResponse(args) => response_replay::execute(args).await,
        Command::Serve(args) => {
            let _telemetry = default_logs();
            Box::pin(ops::serve(args)).await
        }
        Command::Worker(args) => {
            let _telemetry = default_logs();
            Box::pin(ops::worker(*args, getenv)).await
        }
        Command::Migrate(args) => {
            let _telemetry = default_logs();
            ops::migrate(args, out).await
        }
        Command::Admin(args) => {
            let _telemetry = default_logs();
            admin::run(args, out).await
        }
        Command::Config(args) => {
            let _telemetry = default_logs();
            config_check::run(args, out).await
        }
        Command::Mcp(args) => {
            let _telemetry = default_logs();
            mcp::run(args).await
        }
        Command::Healthcheck(args) => healthcheck::run(args, out).await,
        Command::Browser(args) => {
            let _telemetry = default_logs();
            browser_cmd::run(args, out).await
        }
        Command::Authz(args) => {
            let _telemetry = default_logs();
            authz::run(args, out).await
        }
    }
}

fn init_logging(filter: &str, otlp_endpoint: Option<&str>) -> Option<crawlx_telemetry::TelemetryGuard> {
    let cfg = crawlx_telemetry::TelemetryConfig {
        format: crawlx_telemetry::LogFormat::Pretty,
        filter: Some(filter.to_owned()),
        otlp: otlp_endpoint.map(|endpoint| crawlx_telemetry::OtlpConfig {
            endpoint: endpoint.to_owned(),
            service_name: "crawlx".to_owned(),
            resource: Vec::new(),
        }),
        ..crawlx_telemetry::TelemetryConfig::default()
    };
    // a subscriber installed earlier (tests, embedding) wins; a bad OTLP endpoint is reported, not fatal
    match crawlx_telemetry::init(cfg) {
        Ok(guard) => Some(guard),
        Err(crawlx_telemetry::TelemetryError::AlreadyInitialized) => None,
        Err(e) => {
            eprintln!("telemetry: {e}");
            None
        }
    }
}
