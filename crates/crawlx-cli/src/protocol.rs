//! Operator-only local corpus extraction. No HTTP API can construct this root capability.

use crate::extract::OfflineExtractConfig;
use anyhow::{bail, Context};
use clap::Args;
use crawlx_core::extraction::ExtractionPolicyV1;
use crawlx_extract::{ExtractOptions, Extractor};
use crawlx_fetch::protocol::file::FileCorpus;
use crawlx_worker::runtime::CpuPool;
use std::{
    collections::{BTreeSet, VecDeque},
    io::Write,
    num::NonZeroUsize,
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Extract a bounded operator-owned corpus to JSONL on stdout without network access or persistence.
#[derive(Debug, Args)]
pub struct CorpusArgs {
    /// Operator-provided root directory; symlink root is refused.
    #[arg(long)]
    pub root: PathBuf,
    /// Root-relative file URL, for example file:///articles/. Hosts and escapes are refused.
    #[arg(long)]
    pub url: String,
    /// Maximum files and directory entries visited for the entire invocation.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u16).range(1..=4096))]
    pub max_entries: u16,
    /// Maximum approved direct children per directory.
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u16).range(1..=4096))]
    pub max_children: u16,
    /// Total input byte allowance across every file.
    #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u32).range(1..=67_108_864))]
    pub max_bytes: u32,
    /// Whole corpus monotonic deadline, including parsing.
    #[arg(long, default_value_t = 30_000, value_parser = clap::value_parser!(u32).range(1..=90_000))]
    pub timeout_ms: u32,
    /// JSON file, at most 64 KiB, with the `extract` request options `outputs`, `decode` and `markup`.
    #[arg(long, value_name = "CONFIG")]
    pub extract_config: Option<PathBuf>,
}

/// Acquire through safe root-relative descriptors and reuse native extraction/JSON serialization.
///
/// # Errors
/// Fails closed on unsafe paths/files, exhausted traversal/byte/time bounds, parser refusal or output errors.
pub async fn run(args: CorpusArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let url = FileCorpus::parse_url(&args.url)?;
    let corpus = FileCorpus::open(&args.root, usize::from(args.max_children))?;
    let cancel = CancellationToken::new();
    let mut options = ExtractOptions {
        content: Some(ExtractionPolicyV1::default()),
        ..ExtractOptions::default()
    };
    OfflineExtractConfig::load(args.extract_config.as_deref(), &cancel)
        .await?
        .apply(&mut options);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(u64::from(args.timeout_ms));
    let pool = CpuPool::with_permits(NonZeroUsize::MIN);
    let mut pending = VecDeque::from([url]);
    let mut seen = BTreeSet::new();
    let mut bytes_left = args.max_bytes;
    while let Some(url) = pending.pop_front() {
        if !seen.insert(url.as_str().to_owned()) {
            continue;
        }
        if seen.len() > usize::from(args.max_entries) {
            bail!("corpus entry allowance exhausted");
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("corpus deadline exhausted");
        }
        let resource = corpus.acquire(&url, bytes_left, remaining, &cancel).await?;
        if !resource.denied_children.is_empty() {
            bail!("corpus directory contains refused symlink or special entries");
        }
        bytes_left = bytes_left
            .checked_sub(u32::try_from(resource.body.len())?)
            .context("corpus byte allowance exhausted")?;
        if !resource.children.is_empty() {
            if seen
                .len()
                .saturating_add(pending.len())
                .saturating_add(resource.children.len())
                > usize::from(args.max_entries)
            {
                bail!("corpus discovery allowance exhausted");
            }
            pending.extend(resource.children);
            continue;
        }
        if url.path().ends_with('/') && resource.body.is_empty() {
            continue;
        }
        let options = options.clone();
        let task = pool.run(move || {
            let scrubbed =
                crawlx_telemetry::Redactor::new().scrub_bytes(&resource.body, std::iter::empty::<&str>());
            resource_document(scrubbed.as_ref(), &url, &options)
        });
        let (value, _) = tokio::time::timeout_at(deadline, task)
            .await
            .context("corpus parsing deadline exhausted")?
            .context("corpus extraction task failed")??;
        // Shared native serializer; one JSON object per input, no filesystem exporter or live fetch.
        serde_json::to_writer(&mut *out, &value)?;
        out.write_all(b"\n")?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Invoke an explicitly registered isolated protocol service; unavailable services fail without fallback.
#[derive(Debug, Args)]
pub struct ProtocolArgs {
    /// Report only local operator registrations; open no target or service sockets.
    #[arg(long)]
    pub probe: bool,
    /// Explicit target URL; no credentials may appear in URL userinfo.
    #[arg(long, required_unless_present = "probe")]
    pub url: Option<Url>,
    /// Operator-approved delegate key; native_ftp serves only registered origins: anonymous or
    /// credential-reference file reads, and directory listings only where recursion is approved.
    #[arg(long, required_unless_present = "probe")]
    pub delegate: Option<String>,
    /// Operator-selected tenant; registry must explicitly approve this tenant.
    #[arg(long, required_unless_present = "probe")]
    pub tenant: Option<String>,
    /// Operator-selected run ownership.
    #[arg(long, required_unless_present = "probe")]
    pub run: Option<String>,
    /// Unique attempt identity. Reuse is refused by the active client/service nonce ledger.
    #[arg(long, required_unless_present = "probe")]
    pub attempt: Option<String>,
    /// Approved policy revision.
    #[arg(long, required_unless_present = "probe")]
    pub policy_revision: Option<String>,
    /// Explicit protocol ports approved by the operator, including passive data ports.
    #[arg(long, value_delimiter = ',', default_value = "21,22,43")]
    pub allow_ports: Vec<u16>,
    /// Whole response cap.
    #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u32).range(1..=67_108_864))]
    pub max_bytes: u32,
    /// Whole invocation deadline.
    #[arg(long, default_value_t = 30_000, value_parser = clap::value_parser!(u32).range(1..=90_000))]
    pub timeout_ms: u32,
    /// JSON file, at most 64 KiB, with the `extract` request options `outputs`, `decode` and `markup`.
    #[arg(long, value_name = "CONFIG")]
    pub extract_config: Option<PathBuf>,
}

/// Acquire real protocol bytes and extract locally, with diagnostic provenance and no retained provider artifacts.
///
/// # Errors
/// Refuses absent registry, tenant approval, malformed scope, unavailable capability and every protocol boundary failure.
pub async fn acquire(args: ProtocolArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let registry = crawlx_worker::protocol::ProtocolRegistry::from_operator_env().await?;
    if args.probe {
        serde_json::to_writer(
            &mut *out,
            &crawlx_worker::protocol::capability_report(registry.as_deref()),
        )?;
        out.write_all(b"\n")?;
        return Ok(ExitCode::SUCCESS);
    }
    let extract_config =
        OfflineExtractConfig::load(args.extract_config.as_deref(), &CancellationToken::new()).await?;
    let url = args.url.context("protocol target required")?;
    let delegate = args.delegate.context("protocol delegate required")?;
    let attempt = args.attempt.context("protocol attempt required")?;
    let policy_revision = args
        .policy_revision
        .context("protocol policy revision required")?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(u64::from(args.timeout_ms));
    if !matches!(url.scheme(), "ftp" | "sftp" | "whois" | "http" | "https") {
        bail!("protocol service requires an explicitly supported network scheme; use corpus for file");
    }
    if args.allow_ports.len() > 32 || args.allow_ports.contains(&0) {
        bail!("invalid approved protocol port set");
    }
    if matches!(url.scheme(), "http" | "https") {
        let proposed = crawlx_url::Canonicalizer::canonicalize_detailed(
            url.as_str(),
            &url,
            &crawlx_url::CanonicalizeOptions::default(),
        )?;
        if proposed.action_bearing {
            bail!("action-bearing URLs require native Session Actor admission");
        }
    }
    let registry = registry.context("protocol capability unavailable: operator registry absent")?;
    let tenant = args
        .tenant
        .context("protocol tenant required")?
        .parse::<crawlx_core::TenantId>()
        .context("invalid tenant identity")?;
    let run = args
        .run
        .context("protocol run required")?
        .parse::<crawlx_core::CrawlRunId>()
        .context("invalid run identity")?;
    let route: crawlx_core::protocol::ProtocolRouteV1 = serde_json::from_value(serde_json::json!({
        "id":"operator-cli", "schemes":[url.scheme()], "origin":null, "pathPattern":null,
        "schedulerMetadata":{}, "backend":"delegate", "delegateId":delegate,
        "requiredCapabilities":[], "maxBodyBytes":args.max_bytes, "maxElapsedMs":args.timeout_ms,
        "policyRevision":policy_revision
    }))?;
    let crawl = crawlx_core::CreateCrawl::new(url.clone());
    let egress = crawlx_worker::config::EgressConfig {
        extra_ports: args.allow_ports,
        ..Default::default()
    };
    let governor = std::sync::Arc::new(crawlx_fetch::OriginGovernor::new(
        crawlx_fetch::GovernorConfig::default(),
    ));
    let runtime = crawlx_worker::protocol::ProtocolRuntime::new(registry, &egress, &crawl, None, governor)?;
    runtime.admit(std::slice::from_ref(&route), run, tenant, &url, true)?;
    let cancel = CancellationToken::new();
    let requests = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(64));
    let resource = runtime
        .acquire(&route, &url, run, tenant, &attempt, true, &requests, &cancel)
        .await?;
    let mut metadata = crawlx_worker::protocol::resource_metadata(&resource, &route, &url, run, tenant);
    let base = resource.final_url.clone().unwrap_or(url);
    let mut context = crawlx_core::acquisition::ValidationContextV1::default();
    context.target_status = resource.target_status;
    context.transport_succeeded = true;
    let mut options = ExtractOptions {
        status: resource.target_status.unwrap_or(0),
        content_type: resource.media_type,
        content: Some(ExtractionPolicyV1::default()),
        acquisition_validation: Some(context),
        ..ExtractOptions::default()
    };
    extract_config.apply(&mut options);
    let pool = CpuPool::with_permits(NonZeroUsize::MIN);
    let task = pool.run(move || {
        let scrubbed =
            crawlx_telemetry::Redactor::new().scrub_bytes(&resource.body, std::iter::empty::<&str>());
        resource_document(scrubbed.as_ref(), &base, &options)
    });
    let (document, validation) = tokio::time::timeout_at(deadline, task)
        .await
        .context("protocol extraction deadline exhausted")?
        .context("protocol extraction task failed")??;
    metadata.extraction_succeeded = Some(true);
    if let Some(validation) = validation {
        metadata.validation = validation;
    }
    let rejected = metadata
        .target_status
        .is_some_and(|status| !(200..=299).contains(&status));
    serde_json::to_writer(
        &mut *out,
        &serde_json::json!({"lane":"diagnostic","acquisition":metadata,"document":document}),
    )?;
    out.write_all(b"\n")?;
    Ok(if rejected {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn resource_document(
    body: &[u8],
    base: &Url,
    options: &ExtractOptions,
) -> anyhow::Result<(
    serde_json::Value,
    Option<crawlx_core::acquisition::ValidationOutcomeV1>,
)> {
    use crawlx_extract::parse::{detect_format, parse_document, ParseFormat, ParseLimits};
    let limits = ParseLimits::default();
    let format = detect_format(body, Some(base.path()), options.content_type.as_deref(), &limits)?;
    if format == ParseFormat::Html {
        let document = Extractor::extract_bytes(body, base, options)?;
        let validation = document.validation.clone();
        let mut bytes = Vec::new();
        crawlx_extract::serialize::write_article(
            &mut bytes,
            &document,
            crawlx_extract::serialize::ArticleFormat::Json,
        )?;
        return Ok((serde_json::from_slice(&bytes)?, validation));
    }
    let parsed = parse_document(body, Some(base.path()), options.content_type.as_deref(), &limits)?;
    Ok((
        serde_json::json!({
            "schemaVersion":1,"representation":"parsed_document","format":parsed.format.name(),"contentType":parsed.content_type,
            "sourceUrl":base,"title":parsed.title,"markdown":parsed.markdown,"html":parsed.html,"rawHtml":parsed.raw_html,
            "text":parsed.text,"links":parsed.links,"images":parsed.images,"metadata":parsed.metadata,
            "numPages":parsed.num_pages,"totalPages":parsed.total_pages,"pages":parsed.pages,"layout":parsed.layout,"warnings":parsed.warnings
        }),
        None,
    ))
}
