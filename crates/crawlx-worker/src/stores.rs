//! The repositories of one worker process: PostgreSQL when `database_url` is set, otherwise
//! the in-memory store (CLI local runs and tests). Artifacts always go to the filesystem store.

use crate::authorization::{AuthorizationSource, PgAuthorizationSource};
use crate::config::WorkerConfig;
use crate::error::WorkerError;
use crawlx_core::dataset::{DatasetRepo, DeliveryOutboxRepo, KvRepo};
use crawlx_core::orchestration::RequestCommitRepo;
use crawlx_core::repo::{
    ActionJournal, ArtifactStore, CheckpointRepo, EdgeStore, EventRepo, FrontierRepo, IdentityAliasRepo,
    LedgerRepo, ModelDecisionRepo, PageRepo, RunRepo, SafetyAudit, StateRepo,
};
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_storage::artifact_key_crypto::{ArtifactKeys, MemoryArtifactKeys, UnavailableArtifactKeys};
use crawlx_storage::custody::PgSecretAuthority;
use crawlx_storage::{
    ArtifactCustody, BufferLimits, CustodyWrites, DeliveryBuffer, FsArtifactStore, LeaseRepo,
    LeasedSecretRegistrar, LocalArtifactCustody, MemoryStore, Pg, PgArtifactCustody, PgConfig, UploadSpool,
};
use std::path::Path;
use std::sync::Arc;

/// Every repository trait object a worker needs.
#[derive(Clone)]
pub struct Stores {
    /// Runs.
    pub runs: Arc<dyn RunRepo>,
    /// Frontier.
    pub frontier: Arc<dyn FrontierRepo>,
    /// Fenced request result transactions, including accepted items and delivery intent.
    pub request_commits: Arc<dyn RequestCommitRepo>,
    /// Append-only accepted items.
    pub datasets: Arc<dyn DatasetRepo>,
    /// Versioned run-local state.
    pub kv: Arc<dyn KvRepo>,
    /// Tenant-scoped bounded source memo and retention-aware category cache.
    pub source_memo: Arc<dyn crawlx_core::dataset::memo::SourceMemoRepo>,
    /// Fenced durable delivery receipts.
    pub delivery: Arc<dyn DeliveryOutboxRepo>,
    /// Principal-scoped structural selector descriptors.
    pub adaptive_selectors: Arc<dyn crawlx_core::cache::AdaptiveSelectorRepo>,
    /// Retention-bound archive catalog and finalization leases.
    pub archives: Arc<dyn crawlx_core::archive_catalog::ArchiveRepo>,
    /// Pages.
    pub pages: Arc<dyn PageRepo>,
    /// Journal.
    pub journal: Arc<dyn ActionJournal>,
    /// States.
    pub states: Arc<dyn StateRepo>,
    /// Edges.
    pub edges: Arc<dyn EdgeStore>,
    /// Ledger.
    pub ledger: Arc<dyn LedgerRepo>,
    /// Audit.
    pub audit: Arc<dyn SafetyAudit>,
    /// Events.
    pub events: Arc<dyn EventRepo>,
    /// Model decisions (`model_decisions`): System 1 calls kept for audit and shadow comparison.
    pub model_decisions: Arc<dyn ModelDecisionRepo>,
    /// Identity aliases (`identity_aliases`): ambiguous-band resolutions.
    pub identity_aliases: Arc<dyn IdentityAliasRepo>,
    /// Leases.
    pub leases: Arc<dyn LeaseRepo>,
    /// Checkpoints.
    pub checkpoints: Arc<dyn CheckpointRepo>,
    /// Checkpoint secret custody; durable workers require an operator KMS provider.
    pub checkpoint_keys: Arc<dyn crawlx_storage::checkpoint_crypto::CheckpointKeys>,
    /// Artifacts.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Run-wide artifact custody the artifact store publishes through. `None` for
    /// stores whose artifact store writes without it (tests that install their own store):
    /// their CAPTCHA tokens stay in the run-local registry.
    pub custody: Option<Arc<dyn ArtifactCustody>>,
    /// Same quota authority used by artifact writes; required before dispatching delivery content.
    pub delivery_spool: Option<Arc<UploadSpool>>,
    /// The tenant runs created by this process belong to.
    pub tenant: TenantId,
    /// Set for in-memory stores.
    pub memory: Option<Arc<MemoryStore>>,
    /// Set for PostgreSQL stores.
    pub pg: Option<Pg>,
    /// Deployment admission pools shared by all runs backed by this store.
    pub origin_admission: Option<Arc<crawlx_storage::origin::PgOriginAdmission>>,
    /// Where a running worker re-reads the authorization record of a run: the stored record in
    /// PostgreSQL ([`PgAuthorizationSource`]), `None` for in-memory stores until a test or an
    /// in-process run installs one ([`Self::with_authorization_source`]).
    pub authorization: Option<Arc<dyn AuthorizationSource>>,
}

/// Under the `chaos` feature the journal is wrapped in [`crate::chaos::FailingJournal`] so
/// `CRAWLX_FAILPOINTS=during_outcome_tx=...` reaches T2; otherwise `journal` is returned as is.
fn journal_with_failpoints(journal: Arc<dyn ActionJournal>) -> Arc<dyn ActionJournal> {
    #[cfg(feature = "chaos")]
    {
        Arc::new(crate::chaos::FailingJournal::new(journal))
    }
    #[cfg(not(feature = "chaos"))]
    {
        journal
    }
}

/// What a PostgreSQL worker lacks when it cannot seal the artifacts it publishes.
const CUSTODY_CONFIG_HELP: &str = "encrypted artifact custody is not configured: set exactly one of \
     CRAWLX_ARTIFACT_KMS_KEY_ID or CRAWLX_ARTIFACT_KEY_FILE, and CRAWLX_SECRET_REDIS_URL (or \
     CRAWLX_SECRET_REDIS_URL_FILE) naming the persistence-free secret registry";

impl Stores {
    /// Revoke recovery content at the terminal transition, then erase its physical objects.
    /// Backend failure remains an error; the artifact index retains the erasure cursor.
    pub(crate) async fn finish_run(
        &self,
        run: crawlx_core::CrawlRunId,
        reason: crawlx_core::counters::TerminalReason,
        cpu: &crate::runtime::CpuPool,
    ) -> Result<(), crawlx_core::StoreError> {
        let Some(reason) = self
            .request_commits
            .begin_feed_finalization(run, Some(reason))
            .await?
        else {
            self.artifacts.erase_run_credentials(run).await?;
            return Ok(());
        };
        self.delivery.maintain(run).await?;
        let owner = Box::new(self.runs.get(run).await?);
        Box::pin(crate::delivery::finalize_feeds(self, &owner, reason, cpu)).await?;
        self.artifacts.erase_run_credentials(run).await?;
        Ok(())
    }

    /// Build stores over `store` with filesystem artifacts under `artifacts_dir`.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn over_memory(store: Arc<MemoryStore>, artifacts_dir: &Path) -> Result<Self, WorkerError> {
        Self::over_memory_with_spool(store, artifacts_dir, Arc::new(UploadSpool::default()), None).await
    }

    /// [`Self::over_memory`] whose artifact store seals Content and Sensitive artifacts through a
    /// single-process [`LocalArtifactCustody`] and an in-memory key provider, as local runs do.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn over_memory_with_local_custody(
        store: Arc<MemoryStore>,
        artifacts_dir: &Path,
    ) -> Result<Self, WorkerError> {
        Self::over_memory_with_local_custody_keys(store, artifacts_dir, None).await
    }

    /// [`Self::over_memory_with_local_custody`] with an operator key provider (`keys`) instead of
    /// an ephemeral in-memory one when one is configured.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn over_memory_with_local_custody_keys(
        store: Arc<MemoryStore>,
        artifacts_dir: &Path,
        keys: Option<Arc<dyn ArtifactKeys>>,
    ) -> Result<Self, WorkerError> {
        let keys: Arc<dyn ArtifactKeys> = match keys {
            Some(keys) => keys,
            None => Arc::new(MemoryArtifactKeys::new().map_err(custody_error)?),
        };
        Self::over_memory_with_spool(
            store,
            artifacts_dir,
            Arc::new(UploadSpool::default()),
            Some((Arc::new(LocalArtifactCustody::new()), keys)),
        )
        .await
    }

    async fn over_memory_with_spool(
        store: Arc<MemoryStore>,
        artifacts_dir: &Path,
        spool: Arc<UploadSpool>,
        custody: Option<(Arc<dyn ArtifactCustody>, Arc<dyn ArtifactKeys>)>,
    ) -> Result<Self, WorkerError> {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let runs: Arc<dyn RunRepo> = store.clone();
        let zdr = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
        store.set_dataset_delivery(zdr.clone());
        let artifacts = FsArtifactStore::open(artifacts_dir, runs, clock)
            .await?
            .with_index(store.clone())
            .with_zdr_buffer(zdr)
            .with_upload_spool(spool.clone());
        let (artifacts, custody) = match custody {
            Some((custody, keys)) => (
                artifacts.with_custody(Arc::clone(&custody), keys, CustodyWrites::Required),
                Some(custody),
            ),
            None => (artifacts, None),
        };
        Ok(Self {
            runs: store.clone(),
            frontier: store.clone(),
            request_commits: store.clone(),
            datasets: store.clone(),
            kv: store.clone(),
            source_memo: store.clone(),
            delivery: store.clone(),
            adaptive_selectors: store.clone(),
            archives: store.clone(),
            pages: store.clone(),
            journal: journal_with_failpoints(store.clone()),
            states: store.clone(),
            edges: store.clone(),
            ledger: store.clone(),
            audit: store.clone(),
            events: store.clone(),
            model_decisions: store.clone(),
            identity_aliases: store.clone(),
            leases: store.clone(),
            checkpoints: store.clone(),
            checkpoint_keys: store
                .checkpoint_keys()
                .map_err(crate::error::SessionError::from)?,
            artifacts: Arc::new(artifacts),
            custody,
            delivery_spool: Some(spool),
            tenant: TenantId::new(),
            memory: Some(store),
            authorization: None,
            pg: None,
            origin_admission: None,
        })
    }

    /// Open the stores `cfg` asks for.
    ///
    /// Every artifact a worker publishes is sealed through run-wide custody: PostgreSQL mode
    /// requires the key provider and the secret registry endpoint (see
    /// [`WorkerConfig::load_artifact_custody_from_lookup`]); in-memory mode uses a
    /// single-process authority and the configured key provider, or an ephemeral one.
    ///
    /// # Errors
    /// Fails when custody is not configured in PostgreSQL mode, or when a storage, browser or
    /// network operation it depends on fails.
    pub async fn open(cfg: &WorkerConfig) -> Result<Self, WorkerError> {
        match &cfg.database_url {
            None => {
                let keys: Arc<dyn ArtifactKeys> = match &cfg.artifact_keys {
                    Some(keys) => Arc::clone(keys),
                    None => Arc::new(MemoryArtifactKeys::new().map_err(custody_error)?),
                };
                Self::over_memory_with_spool(
                    Arc::new(MemoryStore::new()),
                    &cfg.artifacts_dir,
                    Arc::new(UploadSpool::new(cfg.artifact_spool.clone())?),
                    Some((Arc::new(LocalArtifactCustody::new()), keys)),
                )
                .await
            }
            Some(url) => {
                let keys = cfg
                    .artifact_keys
                    .clone()
                    .ok_or_else(|| WorkerError::Config(CUSTODY_CONFIG_HELP.into()))?;
                let registry = cfg
                    .secret_redis_url
                    .as_ref()
                    .ok_or_else(|| WorkerError::Config(CUSTODY_CONFIG_HELP.into()))?;
                let pg = Pg::connect(url, PgConfig::default()).await?;
                let authority =
                    PgSecretAuthority::open(pg.clone(), registry.expose(), cfg.secret_authority_ttl)
                        .await
                        .map_err(|error| {
                            WorkerError::Config(format!("secret registry is unavailable: {error}"))
                        })?;
                let custody: Arc<dyn ArtifactCustody> = Arc::new(PgArtifactCustody::new(authority));
                Self::open_pg(cfg, pg, custody, keys, CustodyWrites::Required).await
            }
        }
    }

    /// Open PostgreSQL stores that only read artifacts: reports and exports decrypt sealed
    /// artifacts through the catalog but never publish, so no secret registry is needed. A
    /// missing key provider leaves sealed artifacts unreadable with a clear error.
    ///
    /// # Errors
    /// Fails when a storage operation fails.
    pub async fn open_read_only(cfg: &WorkerConfig) -> Result<Self, WorkerError> {
        let Some(url) = &cfg.database_url else {
            return Self::open(cfg).await;
        };
        let keys: Arc<dyn ArtifactKeys> = match &cfg.artifact_keys {
            Some(keys) => Arc::clone(keys),
            None => Arc::new(UnavailableArtifactKeys),
        };
        let pg = Pg::connect(url, PgConfig::default()).await?;
        let custody: Arc<dyn ArtifactCustody> = Arc::new(PgArtifactCustody::new(
            PgSecretAuthority::finalized_reads(pg.clone()),
        ));
        Self::open_pg(cfg, pg, custody, keys, CustodyWrites::ReadOnly).await
    }

    async fn open_pg(
        cfg: &WorkerConfig,
        pg: Pg,
        custody: Arc<dyn ArtifactCustody>,
        keys: Arc<dyn ArtifactKeys>,
        writes: CustodyWrites,
    ) -> Result<Self, WorkerError> {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let zdr = Arc::new(DeliveryBuffer::open_runtime(clock.clone(), BufferLimits::default()).await?);
        let pg = pg.with_delivery_buffer(zdr.clone());
        let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
        let spool = Arc::new(UploadSpool::new(cfg.artifact_spool.clone())?);
        let artifacts = FsArtifactStore::open(&cfg.artifacts_dir, runs, clock)
            .await?
            .with_index(Arc::new(pg.clone()))
            .with_zdr_buffer(zdr)
            .with_upload_spool(spool.clone())
            .with_custody(Arc::clone(&custody), keys, writes);
        let mut stores = Self::over_pg(pg, Arc::new(artifacts), TenantId::new());
        stores.delivery_spool = Some(spool);
        stores.custody = Some(custody);
        Ok(stores)
    }

    /// Stores over an already connected `pg`.
    #[must_use]
    pub fn over_pg(pg: Pg, artifacts: Arc<dyn ArtifactStore>, tenant: TenantId) -> Self {
        Self {
            runs: Arc::new(pg.clone()),
            frontier: Arc::new(pg.clone()),
            request_commits: Arc::new(pg.clone()),
            datasets: Arc::new(pg.clone()),
            kv: Arc::new(pg.clone()),
            source_memo: Arc::new(pg.clone()),
            delivery: Arc::new(pg.clone()),
            adaptive_selectors: Arc::new(pg.clone()),
            archives: Arc::new(pg.clone()),
            pages: Arc::new(pg.clone()),
            journal: journal_with_failpoints(Arc::new(pg.clone())),
            states: Arc::new(pg.clone()),
            edges: Arc::new(pg.clone()),
            ledger: Arc::new(pg.clone()),
            audit: Arc::new(pg.clone()),
            events: Arc::new(pg.clone()),
            identity_aliases: Arc::new(pg.clone()),
            model_decisions: Arc::new(pg.clone()),
            leases: Arc::new(pg.clone()),
            checkpoints: Arc::new(pg.clone()),
            checkpoint_keys: Arc::new(crawlx_storage::checkpoint_crypto::UnavailableCheckpointKeys),
            artifacts,
            delivery_spool: None,
            custody: None,
            tenant,
            memory: None,
            authorization: Some(Arc::new(PgAuthorizationSource::new(pg.clone()))),
            origin_admission: Some(Arc::new(crawlx_storage::origin::PgOriginAdmission::new(
                pg.clone(),
                crawlx_fetch::GlobalOriginCap::DEFAULT_LIMIT,
            ))),
            pg: Some(pg),
        }
    }

    /// Origin capacity for one run, sharing the deployment authority across tenants.
    #[must_use]
    pub fn origin_cap(
        &self,
        cfg: &WorkerConfig,
        run: crawlx_core::CrawlRunId,
        per_run_limit: usize,
    ) -> Arc<crawlx_fetch::GlobalOriginCap> {
        match &self.origin_admission {
            Some(store) => Arc::new(crawlx_fetch::GlobalOriginCap::with_shared_admission(
                Arc::clone(&cfg.origin_cap),
                Arc::new(
                    store
                        .as_ref()
                        .clone()
                        .with_limit(cfg.origin_cap.limit())
                        .for_run(run, per_run_limit),
                ),
            )),
            None => Arc::clone(&cfg.origin_cap),
        }
    }

    /// These stores with `source` as the place authorization records are re-read from.
    #[must_use]
    pub fn with_authorization_source(mut self, source: Arc<dyn AuthorizationSource>) -> Self {
        self.authorization = Some(source);
        self
    }

    /// The producer scope of one leased session: its fence, its run, this worker.
    #[must_use]
    pub(crate) fn session_producer(
        &self,
        run: crawlx_core::CrawlRunId,
        lease: &crawlx_storage::SessionLease,
    ) -> crawlx_core::custody::CustodyLease {
        crawlx_core::custody::CustodyLease::new(
            self.tenant,
            run,
            lease.session.id,
            lease.worker,
            lease.fencing_token,
        )
    }

    /// A registrar that registers run-wide under `lease` and mirrors into `local`; `None` when
    /// this store has no custody (the run-local registry then is the only one).
    #[must_use]
    pub(crate) fn secret_registrar(
        &self,
        lease: crawlx_core::custody::CustodyLease,
        local: &crawlx_core::captcha::CaptchaSecrets,
    ) -> Option<Arc<dyn crawlx_core::custody::SecretRegistrar>> {
        self.custody.as_ref().map(|custody| {
            Arc::new(LeasedSecretRegistrar::new(
                Arc::clone(custody),
                lease,
                local.clone(),
            )) as Arc<dyn crawlx_core::custody::SecretRegistrar>
        })
    }
}

fn custody_error(error: impl std::fmt::Display) -> WorkerError {
    WorkerError::Config(format!("artifact key custody: {error}"))
}
