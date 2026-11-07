//! Isolated local archive replay and baseline QA. Never contacts a live origin.

use anyhow::{anyhow, bail, Context as _};
use clap::Args;
use crawlx_core::config::{CreateCrawl, RetentionMode};
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::repo::{CrawlRun, RunRepo, Sensitivity};
use crawlx_core::secret::ArtifactSink;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{ArtifactRef, CrawlRunId, TenantId};
use crawlx_storage::artifacts::{BoundedArtifactError, FsArtifactStore};
use crawlx_storage::memory::MemoryStore;
use crawlx_worker::archive_replay::{ReplayArchive, ReplayReport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Render a validated retained WARC/WACZ using only the owned local replay origin.
#[derive(Args, Debug)]
pub struct ReplayArgs {
    /// Local WARC, WARC.gz or WACZ; no live URL input is accepted.
    pub input: PathBuf,
    /// Tenant that owns the explicit local content output.
    #[arg(long)]
    pub tenant: TenantId,
    /// New private artifact-store directory. Existing paths are never overwritten.
    #[arg(long)]
    pub out: PathBuf,
    /// Deterministic page-sampling seed, recorded in the result.
    #[arg(long, default_value_t = 0)]
    pub seed: u64,
    /// Maximum sampled HTML pages, 1..32.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=32))]
    pub sample: u8,
    /// Bounded regex over original HTML page URLs, applied before seeded sampling.
    #[arg(long)]
    pub page_filter: Option<String>,
    /// Content retention days, 1..30, enforced by the normal artifact store.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=30))]
    pub retention_days: u8,
    /// Refuse this content-bearing operation before reading input or opening a browser.
    #[arg(long)]
    pub zero_data_retention: bool,
    /// Authorized directory capability for explicitly supplied dependency archives.
    #[arg(long, requires = "dependency")]
    pub dependency_root: Option<PathBuf>,
    /// Approved relative dependency path and exact SHA-256, repeated as PATH=SHA256.
    #[arg(long, value_name = "PATH=SHA256", requires = "dependency_root")]
    pub dependency: Vec<String>,
}

/// Compare an actual isolated render against a retained pinned replay bundle.
#[derive(Args, Debug)]
pub struct QaArgs {
    /// Actual replay inputs and a new retained output directory.
    #[command(flatten)]
    pub replay: ReplayArgs,
    /// Previous replay directory. Absent means not evaluated, never a perfect match.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// Maximum normalized decoded pixel-channel distance, 0..1.
    #[arg(long, default_value_t = 0.0)]
    pub max_pixel_distance: f64,
    /// Maximum normalized Unicode Levenshtein distance, 0..1.
    #[arg(long, default_value_t = 0.0)]
    pub max_text_distance: f64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: u8,
    tenant: TenantId,
    run: CrawlRunId,
    expires_at: chrono::DateTime<chrono::Utc>,
    report: ArtifactRef,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReport {
    report: ReplayReport,
    captures: BTreeMap<String, ArtifactRef>,
}

fn key(page: usize, kind: &str) -> String {
    format!("{page}/{kind}")
}

async fn render(args: &ReplayArgs) -> anyhow::Result<ReplayReport> {
    if args.zero_data_retention {
        bail!("retention_denied: durable archive replay and QA are forbidden under zero data retention");
    }
    if args.out.exists() {
        bail!("archive replay output already exists");
    }
    if !(1..=30).contains(&args.retention_days) {
        bail!("replay retention days must be 1..30");
    }
    if args.dependency.len() >= crawlx_storage::archive::Limits::default().resources {
        bail!("replay dependency count exceeds bound");
    }
    let path = args.input.clone();
    let tenant = args.tenant;
    let dependency_root = args.dependency_root.clone();
    let specifications = args.dependency.clone();
    let archive = tokio::task::spawn_blocking(move || {
        let maximum = crawlx_worker::archive_replay::MAX_ENCODED_BYTES;
        if !path.metadata()?.is_file() {
            bail!("archive replay input must be a regular local file");
        }
        let input = std::fs::File::open(&path)?;
        let metadata = input.metadata()?;
        if !metadata.is_file() || metadata.len() > maximum {
            bail!("archive replay encoded byte bound exceeded");
        }
        let mut snapshot = Vec::with_capacity(usize::try_from(metadata.len())?);
        input.take(maximum + 1).read_to_end(&mut snapshot)?;
        let mut remaining = maximum
            .checked_sub(u64::try_from(snapshot.len())?)
            .ok_or_else(|| anyhow!("archive replay encoded byte bound exceeded"))?;
        let mut dependencies = Vec::with_capacity(specifications.len());
        let mut limits = crawlx_storage::archive::Limits::default();
        limits.total_bytes = remaining;
        if !specifications.is_empty() {
            let root = dependency_root
                .as_deref()
                .ok_or_else(|| anyhow!("replay dependency root required"))?;
            for specification in specifications {
                let (relative, hash) = specification
                    .rsplit_once('=')
                    .ok_or_else(|| anyhow!("dependency must be PATH=SHA256"))?;
                let dependency = crawlx_storage::archive::collection::ApprovedLocalDependency::open(
                    tenant,
                    root,
                    Path::new(relative),
                    hash,
                    limits,
                )?;
                remaining = remaining
                    .checked_sub(dependency.encoded_bytes())
                    .ok_or_else(|| anyhow!("archive dependency byte bound exceeded"))?;
                limits.total_bytes = remaining;
                dependencies.push(dependency);
            }
        }
        Ok::<_, anyhow::Error>(ReplayArchive::from_snapshot(snapshot, tenant, dependencies)?)
    })
    .await??;
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancel.cancel();
        }
    });
    let result = crawlx_worker::archive_replay::replay(
        archive,
        CrawlSeed(args.seed),
        usize::from(args.sample),
        args.page_filter.clone(),
        cancel,
    )
    .await;
    signal.abort();
    let _ = signal.await;
    Ok(result?)
}

async fn save(args: &ReplayArgs, report: ReplayReport) -> anyhow::Result<Bundle> {
    // Reserve exactly one new directory. Cleanup owns only this newly created path.
    tokio::fs::create_dir(&args.out)
        .await
        .context("creating private replay output")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(error) =
            tokio::fs::set_permissions(&args.out, std::fs::Permissions::from_mode(0o700)).await
        {
            let _ = tokio::fs::remove_dir(&args.out).await;
            return Err(error.into());
        }
    }
    let result = save_inner(args, report).await;
    if result.is_err() {
        let _ = tokio::fs::remove_dir_all(&args.out).await;
    }
    result
}

async fn save_inner(args: &ReplayArgs, report: ReplayReport) -> anyhow::Result<Bundle> {
    let now = chrono::Utc::now();
    let mut expires_at = now
        .checked_add_signed(chrono::Duration::days(i64::from(args.retention_days)))
        .ok_or_else(|| anyhow!("replay retention overflow"))?;
    let target = report
        .pages
        .first()
        .ok_or_else(|| anyhow!("replay returned no page"))?
        .target
        .parse()?;
    // This local run exists only to bind real replay artifacts to tenant/retention.
    // It is never scheduled, and its zero counters do not claim live fetch work.
    let mut config = CreateCrawl::new(target);
    config.retention.mode = RetentionMode::Standard;
    config.retention.days = u16::from(args.retention_days);
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: args.tenant,
        status: RunStatus::Completed,
        terminal_reason: Some(TerminalReason::FrontierExhausted),
        config_digest: config.digest()?,
        config,
        seed: report.seed,
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: now,
        started_at: Some(now),
        finished_at: Some(now),
        trace_id: None,
    };
    let runs = Arc::new(MemoryStore::new());
    runs.create(&run, None).await?;
    let store = FsArtifactStore::open(
        args.out.join("artifacts"),
        runs,
        Arc::new(crawlx_core::time::SystemClock),
    )
    .await?;
    let sink = ArtifactSink::over(&store);
    let mut captures = BTreeMap::new();
    for page in &report.pages {
        for capture in &page.captures {
            // Input text passed the archive privacy gate. Runtime text was redacted
            // before reaching this queue; screenshots contain no inherited live jar.
            let class = if capture.media_type == "image/png" {
                Sensitivity::Sensitive
            } else {
                Sensitivity::Content
            };
            if let Some(expiry) = crawlx_storage::retention::artifact_expiry(
                class,
                &capture.media_type,
                RetentionMode::Standard,
                u32::from(args.retention_days),
                now,
            ) {
                expires_at = expires_at.min(expiry);
            }
            let redactor = crawlx_core::secret::Redactor::new();
            let approved = if capture.media_type == "image/png" {
                redactor.verify_binary(&capture.bytes)?
            } else {
                redactor.redact_artifact(&capture.bytes)?
            };
            let reference = sink.put(run.id, class, &capture.media_type, &approved).await?;
            captures.insert(key(page.ordinal, &capture.kind), reference);
        }
    }
    let stored = StoredReport { report, captures };
    let bytes = serde_json::to_vec(&stored)?;
    if bytes.len() > 16 * 1024 * 1024 {
        bail!("replay manifest exceeds 16 MiB bound");
    }
    let approved = crawlx_core::secret::Redactor::new().verify_canonical(&bytes)?;
    let reference = sink
        .put(run.id, Sensitivity::Content, "application/json", &approved)
        .await?;
    let bundle = Bundle {
        schema_version: 1,
        tenant: args.tenant,
        run: run.id,
        expires_at,
        report: reference,
    };
    // Only tenant/run/ref/expiry are outside the normal expiring content store.
    let bytes = serde_json::to_vec_pretty(&bundle)?;
    tokio::fs::write(args.out.join("bundle.json"), bytes).await?;
    Ok(bundle)
}

async fn baseline_artifact(
    store: &FsArtifactStore,
    artifact: &ArtifactRef,
    class: Sensitivity,
    maximum: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    match store.get_bounded(artifact, class, maximum).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(BoundedArtifactError::Store(crawlx_core::StoreError::NotFound { .. })) => Ok(None),
        // Keep raw serde index details inside the library's source chain, not CLI logs.
        Err(BoundedArtifactError::Index(_)) => bail!("baseline artifact index schema invalid"),
        Err(error) => Err(error.into()),
    }
}

async fn load(path: &Path, tenant: TenantId) -> anyhow::Result<Option<ReplayReport>> {
    let bytes = match FsArtifactStore::read_bundle_descriptor(path).await {
        Ok(bytes) => bytes,
        Err(BoundedArtifactError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(error) => return Err(error.into()),
    };
    let bundle: Bundle =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("baseline bundle descriptor schema invalid"))?;
    if bundle.schema_version != 1 || bundle.tenant != tenant {
        bail!("baseline tenant or schema check failed");
    }
    if !path.join("artifacts").is_dir() {
        return Ok(None);
    }
    let store = FsArtifactStore::open(
        path.join("artifacts"),
        Arc::new(MemoryStore::new()),
        Arc::new(crawlx_core::time::SystemClock),
    )
    .await?
    .with_read_scope(tenant, bundle.run);
    if bundle.expires_at <= chrono::Utc::now() {
        return Ok(None);
    }
    let Some(bytes) =
        baseline_artifact(&store, &bundle.report, Sensitivity::Content, 16 * 1024 * 1024).await?
    else {
        return Ok(None);
    };
    let mut stored: StoredReport =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("baseline replay manifest schema invalid"))?;
    if stored.report.pages.len() > 32 || stored.report.resources.len() > 10_000 || stored.captures.len() > 160
    {
        bail!("baseline replay count bound failed");
    }
    let mut remaining = 64 * 1024 * 1024u64;
    for page in &mut stored.report.pages {
        if page.captures.len() > 5 {
            bail!("baseline phase count bound failed");
        }
        page.captures
            .retain(|capture| stored.captures.contains_key(&key(page.ordinal, &capture.kind)));
        for capture in &mut page.captures {
            if !matches!(
                capture.kind.as_str(),
                "initial_text" | "final_text" | "viewport" | "full_page" | "final"
            ) {
                bail!("unknown baseline capture phase");
            }
            let Some(reference) = stored.captures.get(&key(page.ordinal, &capture.kind)) else {
                continue;
            };
            let class = if capture.media_type == "image/png" {
                Sensitivity::Sensitive
            } else {
                Sensitivity::Content
            };
            match baseline_artifact(&store, reference, class, remaining.min(16 * 1024 * 1024)).await? {
                Some(bytes) => {
                    remaining = remaining
                        .checked_sub(u64::try_from(bytes.len())?)
                        .ok_or_else(|| anyhow!("baseline capture byte bound"))?;
                    capture.bytes = bytes;
                }
                None => capture.kind.clear(),
            }
        }
        page.captures.retain(|capture| !capture.kind.is_empty());
    }
    Ok(Some(stored.report))
}

/// Execute a real isolated replay and retain its distinct evidence resources.
///
/// # Errors
/// Returns validation, privacy, retention, pinned-browser, cancellation or output errors.
pub async fn replay(args: ReplayArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let report = render(&args).await?;
    let pages = report.pages.len();
    let missing = report
        .resources
        .iter()
        .filter(|r| r.status == 404 && r.recorded_status.is_none())
        .count();
    let denied = report.denied_requests;
    let bundle = save(&args, report).await?;
    serde_json::to_writer_pretty(
        &mut *out,
        &serde_json::json!({"schemaVersion":1,"operation":"archive_replay",
        "run":bundle.run,"tenant":bundle.tenant,"pages":pages,"missingResources":missing,"deniedRequests":denied,
        "expiresAt":bundle.expires_at,"baselineComparison":"not_evaluated"}),
    )?;
    writeln!(out)?;
    Ok(ExitCode::SUCCESS)
}

/// Execute actual offline replay and compare against a retained pinned baseline.
/// Exit 2 means at least one baseline was absent; exit 1 means measured mismatch.
///
/// # Errors
/// Returns the same validation/isolation errors as replay, or baseline/fixity errors.
pub async fn qa(args: QaArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    if args.replay.zero_data_retention {
        bail!("retention_denied: durable archive QA is forbidden under zero data retention");
    }
    for threshold in [args.max_pixel_distance, args.max_text_distance] {
        if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
            bail!("qa distance thresholds must be 0..1");
        }
    }
    let baseline = match &args.baseline {
        Some(path) => load(path, args.replay.tenant).await?,
        None => None,
    };
    let actual = render(&args.replay).await?;
    let max_pixel = args.max_pixel_distance;
    let max_text = args.max_text_distance;
    let (actual, compared) = tokio::task::spawn_blocking(move || {
        let compared = crawlx_worker::archive_qa::compare(&actual, baseline.as_ref(), max_pixel, max_text)?;
        Ok::<_, crawlx_worker::archive_replay::ReplayError>((actual, compared))
    })
    .await??;
    let _bundle = save(&args.replay, actual).await?;
    serde_json::to_writer_pretty(&mut *out, &compared)?;
    writeln!(out)?;
    Ok(if compared.failed > 0 {
        ExitCode::FAILURE
    } else if compared.not_evaluated > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}
