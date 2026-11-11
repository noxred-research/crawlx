//! Offline retained-source reparsing under the original run's tenant, principal and custody.
//!
//! This command never constructs acquisition, browser, model or remote secret resolvers. It
//! emits a bounded JSON result to stdout only; it cannot create a new retention window.

use anyhow::{bail, Context as _};
use clap::{Args, ValueEnum};
use crawlx_core::acquisition::AcquisitionResultV1;
use crawlx_core::custody::{ArtifactReadState, RunSecretAuthority};
use crawlx_core::extraction::ParserPipelineV1;
use crawlx_core::{CrawlRunId, SystemClock, TenantId};
use crawlx_extract::pipeline::ParserPipeline;
use crawlx_worker::reparse::{
    privacy_from_original_run, ReparseIntent, ReparseServices, RetainedRepresentation,
};
use crawlx_worker::DurableAuthority;
use serde_json::json;
use std::{io::Write, path::PathBuf, process::ExitCode, sync::Arc};
use tokio_util::sync::CancellationToken;

const MAX_OUTPUT: usize = 16 * 1024 * 1024;

/// Exact original retained representation. Neither variant authorizes acquisition.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
#[non_exhaustive]
pub enum RepresentationArg {
    /// Transport-decoded original response bytes.
    #[default]
    WireBody,
    /// Original settled serialized page DOM.
    RenderedDom,
}
impl RepresentationArg {
    fn native(self) -> RetainedRepresentation {
        match self {
            Self::WireBody => RetainedRepresentation::WireBody,
            Self::RenderedDom => RetainedRepresentation::RenderedDom,
        }
    }
}

/// Reparse one existing committed source without fetching any URL.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ReparseArgs {
    /// Existing source run.
    pub run: CrawlRunId,
    /// Exact committed source request identifier.
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    pub frontier: i64,
    /// Original owning tenant; checked against the run and artifact custody.
    #[arg(long)]
    pub tenant: TenantId,
    /// Original admitted request principal; never inferred from source metadata.
    #[arg(long)]
    pub principal: String,
    /// Exact retained source representation.
    #[arg(long, value_enum, default_value = "wire-body")]
    pub representation: RepresentationArg,
    /// Versioned ParserPipelineV1 JSON, at most one MiB. Omit for the native pipeline.
    #[arg(long, value_name = "FILE")]
    pub pipeline: Option<PathBuf>,
    /// Existing metadata database (PostgreSQL, MariaDB or SQLite URL); migrations are never run by this command.
    #[arg(long, env = "CRAWLX_DATABASE_URL", hide_env_values = true)]
    pub database_url: String,
    /// Existing artifact directory; symbolic links and missing roots are refused.
    #[arg(long, default_value = "./crawlx-artifacts", value_name = "DIRECTORY")]
    pub artifacts_dir: PathBuf,
}

fn pipeline(args: &ReparseArgs) -> anyhow::Result<ParserPipeline> {
    if args.principal.is_empty() || args.principal.len() > 256 || args.principal.chars().any(char::is_control)
    {
        bail!("invalid original request principal");
    }
    let mut spec: ParserPipelineV1 = match &args.pipeline {
        Some(path) => serde_json::from_slice(&crate::config_file::read_document(path)?)
            .context("invalid offline parser pipeline JSON")?,
        None => ParserPipelineV1::default(),
    };
    // These are CLI output/inspection ceilings, not changes to the source retention policy.
    spec.limits.max_input_bytes = spec.limits.max_input_bytes.min(8_388_608);
    spec.limits.max_output_bytes = spec.limits.max_output_bytes.min(8_388_608);
    ParserPipeline::new(spec).context("invalid offline parser pipeline")
}

/// Open read-only stores and emit one privacy-projected retained-source result.
///
/// Existing metadata/artifact storage and the original volatile secret authority are the only
/// services contacted. No target URL, browser, model, script or external parser is invoked.
///
/// # Errors
/// Refuses missing/expired/ZDR/foreign sources, unavailable original privacy authority, bad
/// pipeline configuration, cancellation and storage/output failures. Finalized epochs without
/// their original secret registry cannot authorize fresh derived decoding and fail explicitly.
pub async fn execute(args: ReparseArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let parser = pipeline(&args)?;
    let root = tokio::fs::symlink_metadata(&args.artifacts_dir)
        .await
        .context("reading retained artifact directory")?;
    if !root.is_dir() || root.file_type().is_symlink() {
        bail!("retained artifact root must be an existing directory");
    }
    let mut cfg = crawlx_worker::WorkerConfig::default();
    cfg.load_artifact_custody_from_lookup(&|name| std::env::var(name).ok())
        .await?;
    let durable = crate::inspect::connect(Some(&args.database_url)).await?;
    let authority = match &cfg.secret_redis_url {
        Some(url) => {
            DurableAuthority::open_with_policy(
                &durable,
                url.expose(),
                cfg.secret_authority_ttl,
                cfg.secret_authority_hard_max,
            )
            .await?
        }
        None => DurableAuthority::finalized_reads(&durable),
    };
    let keys = cfg
        .artifact_keys
        .take()
        .context("retained artifact key custody is unavailable")?;
    let custody = authority.custody();
    let run_authority = authority.run_authority();
    let cancel = CancellationToken::new();
    let mut watcher = tokio::task::JoinSet::new();
    let signal = cancel.clone();
    watcher.spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    crawlx_storage::tenant::scope(args.tenant, async {
        let artifacts = crawlx_worker::on_store!(&durable, store => {
            crawlx_storage::FsArtifactStore::open(
                &args.artifacts_dir,
                Arc::new(store.clone()),
                Arc::new(SystemClock),
            )
            .await?
            .with_index(Arc::new(store.clone()))
            .with_custody(custody, keys, crawlx_storage::CustodyWrites::ReadOnly)
        });
        let stores = crawlx_worker::Stores::over_durable(durable.clone(), Arc::new(artifacts), args.tenant);
        let services = ReparseServices {
            runs: stores.runs.as_ref(),
            pages: stores.pages.as_ref(),
            frontier: stores.frontier.as_ref(),
            artifacts: stores.artifacts.as_ref(),
            clock: &SystemClock,
        };
        let intent = ReparseIntent::new(
            args.tenant,
            args.run,
            args.frontier,
            args.principal,
            args.representation.native(),
        );
        execute_with_services(&services, &intent, parser, run_authority.as_ref(), out, &cancel).await
    })
    .await
}

/// Bind reparse to existing trusted repositories and original secret authority.
///
/// This entry point allows in-process callers to use the same offline binding without
/// environment changes or signal handlers. It never installs an empty fallback registry.
/// Output is stdout-style JSON only, not a newly retained artifact.
///
/// # Errors
/// Same scope, retention, original-secret, parser, cancellation and output failures as [`execute`].
pub async fn execute_with_services(
    services: &ReparseServices<'_>,
    intent: &ReparseIntent,
    parser: ParserPipeline,
    authority: &dyn RunSecretAuthority,
    out: &mut dyn Write,
    cancel: &CancellationToken,
) -> anyhow::Result<ExitCode> {
    if cancel.is_cancelled() {
        bail!("retained reparse cancelled");
    }
    let run = services.runs.get_for_execution(intent.run).await?;
    if run.tenant != intent.tenant {
        bail!("retained source scope mismatch");
    }
    if run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr {
        bail!("retained reparse denied by retention policy");
    }
    let request = services
        .frontier
        .get_request(intent.run, intent.frontier_id)
        .await?;
    if request.principal != intent.principal {
        bail!("retained source scope mismatch");
    }
    let page = services
        .pages
        .get_committed(intent.run, intent.frontier_id)
        .await?
        .context("retained source unavailable")?;
    let acquisition: AcquisitionResultV1 = serde_json::from_value(
        page.metadata
            .get("acquisition")
            .cloned()
            .context("original acquisition provenance unavailable")?,
    )
    .context("invalid original acquisition provenance")?;
    if acquisition.run != intent.run || acquisition.tenant != intent.tenant || acquisition.truncated {
        bail!("retained source provenance is foreign or truncated");
    }
    let source = match intent.representation {
        RetainedRepresentation::WireBody => acquisition.wire_body,
        RetainedRepresentation::RenderedDom => acquisition.rendered_dom,
        _ => bail!("unsupported retained representation"),
    }
    .context("exact retained representation unavailable")?;
    let snapshot = match authority.read_state(intent.tenant, intent.run, source.id).await? {
        ArtifactReadState::Live(snapshot) => snapshot,
        ArtifactReadState::Finalized(epoch) => {
            authority
                .retained_snapshot(intent.tenant, intent.run, epoch)
                .await?
        }
        _ => bail!("original privacy authority is unavailable"),
    };
    if snapshot.version.tenant != intent.tenant || snapshot.version.run != intent.run {
        bail!("original privacy authority scope mismatch");
    }
    let privacy = privacy_from_original_run(&run, &snapshot)?;
    let result = services.run(intent, parser, privacy, cancel).await?;
    let mut document = json!({
        "version": 1, "sourceRun": intent.run, "sourceFrontier": intent.frontier_id,
        "sourceArtifact": result.source, "representation": match result.representation {
            RetainedRepresentation::WireBody => "wire_body",
            RetainedRepresentation::RenderedDom => "rendered_dom",
            _ => "unsupported",
        },
        "previousRecordVersion": result.previous_record_version,
        "parserDigest": result.parser_digest, "recordVersion": result.output.record_version,
        "networkRequests": 0, "persisted": false,
        "data": {"title": result.output.title(), "text": result.output.text()},
        "stages": result.output.stages, "warningCount": result.output.warnings.len(),
    });
    snapshot.secrets.redact_json(&mut document)?;
    let bytes = crate::scrape::encode_bounded(&document, MAX_OUTPUT)?;
    if snapshot.secrets.contains_bytes(&bytes)? {
        bail!("reparse output failed original secret exclusion");
    }
    let custody = services
        .artifacts
        .archive_custody(intent.tenant, intent.run, &source, u64::try_from(MAX_OUTPUT)?)
        .await?;
    custody.validate(services.clock.now())?;
    let current = authority
        .retained_snapshot(intent.tenant, intent.run, snapshot.version)
        .await?;
    if current.version != snapshot.version {
        bail!("original privacy authority changed during reparse");
    }
    if cancel.is_cancelled() {
        bail!("retained reparse cancelled");
    }
    out.write_all(&bytes)?;
    writeln!(out)?;
    Ok(ExitCode::SUCCESS)
}
