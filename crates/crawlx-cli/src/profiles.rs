//! Operator-only encrypted profile lifecycle. Database credentials and the existing
//! live session lease authenticate access; no API request can self-grant retention.

use anyhow::{anyhow, bail, Context as _};
use clap::{Args, Subcommand};
use crawlx_core::hash::Digest;
use crawlx_core::repo::RunRepo;
use crawlx_core::secret::{CredentialRef, SecretResolver};
use crawlx_core::{CrawlRunId, SessionId, TenantId, WorkerId};
use crawlx_storage::leases::SessionLease;
use crawlx_storage::profiles::{BrowserProfileRepo, ProfileCipher, ProfileScopeV1, MAX_BUNDLE_BYTES};
use crawlx_storage::sql::Sql;
use crawlx_storage::Store;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Authenticated encrypted-profile operations. Nothing opens a browser or fetches a URL.
#[derive(Args, Debug)]
pub struct ProfilesArgs {
    /// Operator database connection (PostgreSQL, MariaDB or SQLite URL). The tenant's existing lease fence remains authority.
    #[arg(long, env = "CRAWLX_DATABASE_URL", global = true, hide_env_values = true)]
    pub database_url: Option<String>,
    /// Owning tenant UUID.
    #[arg(long)]
    pub tenant: TenantId,
    /// Current run UUID, not a historical source run.
    #[arg(long)]
    pub run: CrawlRunId,
    /// Existing leased session UUID.
    #[arg(long)]
    pub session: SessionId,
    /// Existing owning worker UUID.
    #[arg(long)]
    pub worker: WorkerId,
    /// Current database session fencing token. Never creates or renews authority.
    #[arg(long)]
    pub fence: i64,
    /// JSON ProfileScopeV1 file: tenant, principal, name, allowed_origins, backend_build, egress.
    #[arg(long)]
    pub scope: PathBuf,
    /// Secret reference resolving to 64 hex characters (AES-256); never an inline key.
    #[arg(long, env = "CRAWLX_PROFILE_KEY_REF")]
    pub key_ref: String,
    /// Explicit operator approval for imported executable browser preferences/extensions.
    #[arg(long, global = true)]
    pub approve_executable_preferences: bool,
    /// Profile operation.
    #[command(subcommand)]
    pub command: ProfilesCommand,
}

/// Operations on separate encrypted credential-bearing profile artifacts.
#[derive(Subcommand, Debug)]
pub enum ProfilesCommand {
    /// Import an approved digest-pinned native encrypted bundle; plaintext/tar inputs are rejected.
    Import {
        /// Encrypted CXP1 bundle path. No URL download is supported.
        input: PathBuf,
        /// Domain-separated digest printed by profiles export.
        #[arg(long)]
        digest: String,
        /// Existing generation, zero for a new profile. Bundle generation must be exactly next.
        #[arg(long)]
        expected_generation: u64,
        /// Explicit operator approval of retained_profile secret storage.
        #[arg(long)]
        approve_retained_profile: bool,
    },
    /// Export exact encrypted generation, never a plaintext profile directory or ordinary archive.
    Export {
        /// Exact generation to read.
        #[arg(long)]
        generation: u64,
        /// New destination file; existing paths are never overwritten.
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect compatibility, expiry, file count and encrypted fixity without exposing secrets.
    Inspect {
        /// Exact generation to inspect.
        #[arg(long)]
        generation: u64,
    },
    /// Erase actual ciphertext, fenced against concurrent generation changes.
    Delete {
        /// Exact generation to remove.
        #[arg(long)]
        generation: u64,
    },
}

fn bounded_file(path: &std::path::Path, max: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(u64::try_from(max)?.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        bail!("profile input exceeds byte bound");
    }
    Ok(bytes)
}

/// Execute operator profile I/O. Source/ciphertext parsing and final file publication are bounded.
///
/// # Errors
/// Returns invalid scope/key, retention denial, expiry, stale fence or profile generation conflict.
pub async fn run(args: ProfilesArgs) -> anyhow::Result<ExitCode> {
    if !["env://", "file://", "vault://", "cloud-sm://"]
        .iter()
        .any(|scheme| args.key_ref.starts_with(scheme))
    {
        bail!("profile key must be an explicit secret reference, never an inline key");
    }
    let scope_path = args.scope.clone();
    let scope: ProfileScopeV1 = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        Ok(serde_json::from_slice(&bounded_file(&scope_path, 64 * 1024)?)?)
    })
    .await??;
    scope.validate()?;
    if scope.tenant != args.tenant {
        bail!("profile scope tenant does not match operator tenant");
    }
    let durable = crate::inspect::connect(args.database_url.as_deref()).await?;
    crawlx_worker::on_store!(&durable, store => run_on(store, args, scope).await)
}

async fn run_on<B: Sql>(
    pg: &Store<B>,
    args: ProfilesArgs,
    scope: ProfileScopeV1,
) -> anyhow::Result<ExitCode> {
    let run = crawlx_storage::tenant::scope(args.tenant, RunRepo::get_metadata(pg, args.run)).await?;
    if run.tenant != args.tenant {
        bail!("profile run tenant mismatch");
    }
    let session = crawlx_storage::tenant::scope(args.tenant, RunRepo::list_sessions(pg, args.run))
        .await?
        .into_iter()
        .find(|session| session.id == args.session)
        .ok_or_else(|| anyhow!("profile session is absent from the selected run"))?;
    if session.role != scope.principal {
        bail!("profile principal conflict");
    }
    let lease = SessionLease {
        session,
        worker: args.worker,
        fencing_token: args.fence,
        expires_at: chrono::Utc::now(),
    };
    let resolver = crawlx_worker::ChainResolver::from_env(Arc::new(crawlx_core::SystemClock)).await;
    let secret = resolver
        .resolve(&CredentialRef(args.key_ref))
        .await
        .context("profile encryption key resolution failed")?;
    let mut key = zeroize::Zeroizing::new(
        hex::decode(secret.expose())
            .map_err(|_| anyhow!("profile key must resolve to 64 hexadecimal characters"))?,
    );
    let cipher = ProfileCipher::new(&key);
    // The encryption primitive owns its key schedule; do not retain a duplicate decoding buffer.
    key.fill(0);
    let cipher = cipher?;
    let service = BrowserProfileRepo::new(pg, &cipher);
    let result = crawlx_storage::tenant::scope(args.tenant, async {
        match args.command {
            ProfilesCommand::Import {
                input,
                digest,
                expected_generation,
                approve_retained_profile,
            } => {
                if !approve_retained_profile {
                    bail!("retention_denied: --approve-retained-profile is required");
                }
                let pinned =
                    Digest::from_hex(&digest).map_err(|_| anyhow!("invalid profile bundle digest"))?;
                let bytes =
                    tokio::task::spawn_blocking(move || bounded_file(&input, MAX_BUNDLE_BYTES)).await??;
                let inspection = service
                    .import(
                        &lease,
                        &scope,
                        &bytes,
                        pinned,
                        expected_generation,
                        true,
                        args.approve_executable_preferences,
                    )
                    .await?;
                Ok(serde_json::to_value(inspection)?)
            }
            ProfilesCommand::Export { generation, out } => {
                let (inspection, bytes) = service
                    .export(&lease, &scope, generation, args.approve_executable_preferences)
                    .await?;
                tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                    let parent = out
                        .parent()
                        .filter(|path| !path.as_os_str().is_empty())
                        .unwrap_or_else(|| std::path::Path::new("."));
                    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
                    temp.write_all(&bytes)?;
                    temp.as_file_mut().sync_all()?;
                    temp.persist_noclobber(&out).map_err(|error| error.error)?;
                    Ok(())
                })
                .await??;
                Ok(serde_json::to_value(inspection)?)
            }
            ProfilesCommand::Inspect { generation } => Ok(serde_json::to_value(
                service
                    .inspect(&lease, &scope, generation, args.approve_executable_preferences)
                    .await?,
            )?),
            ProfilesCommand::Delete { generation } => {
                service.delete(&lease, &scope, generation).await?;
                Ok(serde_json::json!({"deleted":true,"generation":generation}))
            }
        }
    })
    .await?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &result)?;
    writeln!(stdout)?;
    Ok(ExitCode::SUCCESS)
}
