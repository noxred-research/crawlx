//! Development response replay, distinct from journalled browser action replay.
//! Reads one committed retention-approved artifact with an exact saved request identity.
//! No fetcher, browser, provider, secret resolver, action executor or telemetry is initialized.
use anyhow::Context;
use base64::Engine;
use clap::Args;
use crawlx_core::hash::Digest;
use crawlx_core::{CrawlRunId, TenantId};
use crawlx_storage::artifact_key_crypto::ArtifactKeys;
use crawlx_storage::sql::Sql;
use crawlx_storage::{ArtifactCustody, FsArtifactStore, Store};
use std::{io::Write, path::PathBuf, process::ExitCode, sync::Arc};

/// Read one existing retained response without acquiring a target URL.
#[derive(Debug, Args)]
pub struct ReplayResponseArgs {
    /// Existing source run, not a newly queued replay run.
    pub run: CrawlRunId,
    /// Existing committed page frontier identifier.
    #[arg(long)]
    pub frontier: i64,
    /// Exact saved nativeCache.key or scrape.optionsDigest (64 hexadecimal digits).
    #[arg(long, value_name = "DIGEST")]
    pub identity: String,
    /// Tenant authorized to read the source run.
    #[arg(long)]
    pub tenant: TenantId,
    /// Source API-key principal. Omit only for an isolated local source run.
    #[arg(long)]
    pub principal: Option<uuid::Uuid>,
    /// Database (PostgreSQL, MariaDB or SQLite URL) holding the existing source metadata; migrations are never run here.
    #[arg(long, env = "CRAWLX_DATABASE_URL", value_name = "URL", hide_env_values = true)]
    pub database_url: String,
    /// Existing local artifact root.
    #[arg(long, default_value = "./crawlx-artifacts", value_name = "DIRECTORY")]
    pub artifacts_dir: PathBuf,
    /// Maximum approved artifact bytes read; bounded to 64 MiB.
    #[arg(long, default_value_t = 8_388_608, value_parser = clap::value_parser!(u64).range(1..=67_108_864))]
    pub max_bytes: u64,
}

/// Emit the retained bytes as base64 JSON with explicit zero-target-network provenance.
/// # Errors
/// Returns identity, source ownership, retention, bounded-read, storage or stdout errors.
pub async fn execute(args: ReplayResponseArgs) -> anyhow::Result<ExitCode> {
    let identity = Digest::from_hex(&args.identity).context("invalid saved response identity")?;
    let root = tokio::fs::symlink_metadata(&args.artifacts_dir)
        .await
        .context("reading retained artifact root")?;
    if root.file_type().is_symlink() || !root.is_dir() {
        anyhow::bail!("retained artifact root must be an existing directory");
    }
    let durable = crate::inspect::connect(Some(&args.database_url))
        .await
        .context("opening retained response metadata")?;
    let (custody, keys) =
        crawlx_worker::config::read_only_custody_from_lookup(&durable, &|name| std::env::var(name).ok())
            .await
            .context("opening artifact key custody")?;
    crawlx_worker::on_store!(&durable, store => replay_on(store, custody, keys, &args, identity).await)
}

async fn replay_on<B: Sql>(
    store: &Store<B>,
    custody: Arc<dyn ArtifactCustody>,
    keys: Arc<dyn ArtifactKeys>,
    args: &ReplayResponseArgs,
    identity: Digest,
) -> anyhow::Result<ExitCode> {
    crawlx_storage::tenant::scope(args.tenant, async {
        let artifacts = FsArtifactStore::open(
            &args.artifacts_dir,
            Arc::new(store.clone()),
            Arc::new(crawlx_core::SystemClock),
        )
        .await?
        .with_index(Arc::new(store.clone()))
        .with_custody(custody, keys, crawlx_storage::CustodyWrites::ReadOnly);
        let replay = crawlx_worker::scrape::cache::replay_saved_response(
            store,
            store,
            &artifacts,
            args.tenant,
            args.run,
            args.frontier,
            identity,
            args.principal,
            chrono::Utc::now(),
            args.max_bytes,
        )
        .await?;
        let document = serde_json::json!({
            "version":1,"provenance":"retained_artifacts","sourceRun":replay.page.run,
            "sourceFrontier":replay.page.frontier_id,"sourceFetchedAt":replay.page.fetched_at,
            "requestIdentity":replay.identity,"representation":replay.representation,
            "networkRequests":0,"targetStatus":replay.page.status,"contentType":replay.page.content_type,
            "bodyBase64":base64::engine::general_purpose::STANDARD.encode(&replay.body),
        });
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        serde_json::to_writer(&mut output, &document)?;
        output.write_all(b"\n")?;
        Ok(ExitCode::SUCCESS)
    })
    .await
}
