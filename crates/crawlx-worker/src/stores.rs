//! The repositories of one worker process: the configured database (PostgreSQL, MariaDB or
//! SQLite) when `database_url` is set, otherwise the in-memory store (CLI local runs and tests).
//! Artifacts always go to the filesystem store.

use crate::authorization::{AuthorizationSource, DatabaseAuthorizationSource};
use crate::config::WorkerConfig;
use crate::durable::{DurableAuthority, DurableStore, OriginAdmissions};
use crate::error::WorkerError;
use crawlx_core::dataset::{DatasetRepo, DeliveryOutboxRepo, KvRepo};
use crawlx_core::orchestration::RequestCommitRepo;
use crawlx_core::repo::{
    ActionJournal, ArtifactStore, CheckpointRepo, EdgeStore, EventRepo, FrontierRepo, IdentityAliasRepo,
    LedgerRepo, ModelDecisionRepo, PageRepo, RunRepo, SafetyAudit, StateRepo,
};
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_storage::artifact_key_crypto::{ArtifactKeys, MemoryArtifactKeys, UnavailableArtifactKeys};
use crawlx_storage::sql::Sql;
use crawlx_storage::{
    ArtifactCustody, BackendRefusal, BufferLimits, CustodyWrites, Database, DeliveryBuffer, FsArtifactStore,
    LeaseRepo, LeasedSecretRegistrar, LocalArtifactCustody, MemoryStore, S3ArtifactStore, S3Blobs, S3Config,
    Store, UploadSpool, WorkerLock,
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
    /// Durable exact-binding reviewer approval repository.
    pub approvals: Arc<dyn crawlx_storage::approvals::ApprovalRepository>,
    /// Tenant-scoped bounded measured processor history.
    pub report_history: Arc<dyn crawlx_core::report_history::ReportHistoryRepo>,
    /// Privacy-safe versioned URL graph repository.
    pub url_graph: Arc<dyn crawlx_core::url_graph::UrlGraphRepo>,
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
    /// Shared renewable authority; absent for memory and read-only stores.
    pub secret_authority: Option<Arc<DurableAuthority>>,
    /// Exact artifact key provider shared by structured profile custody.
    pub artifact_keys: Option<Arc<dyn ArtifactKeys>>,
    /// Same quota authority used by artifact writes; required before dispatching delivery content.
    pub delivery_spool: Option<Arc<UploadSpool>>,
    /// The tenant runs created by this process belong to.
    pub tenant: TenantId,
    /// Set for in-memory stores.
    pub memory: Option<Arc<MemoryStore>>,
    /// Set for database stores, whatever the engine.
    pub durable: Option<DurableStore>,
    /// Deployment admission pools shared by all runs backed by this store.
    pub origin_admission: Option<Arc<OriginAdmissions>>,
    /// The exclusive worker lock of a SQLite database file, held while these stores live.
    pub worker_lock: Option<Arc<WorkerLock>>,
    /// Where a running worker re-reads the authorization record of a run: the stored record in
    /// a database deployment ([`DatabaseAuthorizationSource`]), `None` for in-memory stores until a
    /// test or an in-process run installs one ([`Self::with_authorization_source`]).
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

impl Stores {
    /// Revoke recovery content at the terminal transition, then erase its physical objects.
    /// Backend failure remains an error; the artifact index retains the erasure cursor.
    pub(crate) async fn finish_run(
        &self,
        run: crawlx_core::CrawlRunId,
        reason: crawlx_core::counters::TerminalReason,
        cpu: &crate::runtime::CpuPool,
        worker: crawlx_core::WorkerId,
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
        Box::pin(crate::delivery::finalize_feeds(self, &owner, reason, cpu, worker)).await?;
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
        let artifact_keys = custody.as_ref().map(|(_, keys)| Arc::clone(keys));
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
            approvals: store.clone(),
            report_history: store.clone(),
            url_graph: store.clone(),
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
            secret_authority: None,
            artifact_keys,
            delivery_spool: Some(spool),
            tenant: TenantId::new(),
            memory: Some(store),
            authorization: None,
            durable: None,
            origin_admission: None,
            worker_lock: None,
        })
    }

    /// Open the stores `cfg` asks for.
    ///
    /// Every artifact a worker publishes is sealed through run-wide custody: database mode
    /// requires the key provider and the secret registry endpoint (see
    /// [`WorkerConfig::load_artifact_custody_from_lookup`]); in-memory mode uses a
    /// single-process authority and the configured key provider, or an ephemeral one.
    ///
    /// # Errors
    /// Fails with the `custody_missing` refusal when custody is not configured in database mode,
    /// with the engine's refusals (a second worker on one SQLite file, unsupported servers) and
    /// when a storage, browser or network operation it depends on fails.
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
                    .ok_or_else(|| WorkerError::Refused(BackendRefusal::custody_missing()))?;
                let registry = cfg
                    .secret_redis_url
                    .as_ref()
                    .ok_or_else(|| WorkerError::Refused(BackendRefusal::custody_missing()))?;
                let database = Database::open(url, cfg.store.clone()).await?;
                crate::durable::check_sqlite_single_tenant(&database, &[]).await?;
                let worker_lock = database.acquire_worker_lock()?.map(Arc::new);
                let durable = DurableStore::open(&database)?;
                let authority = DurableAuthority::open_with_policy(
                    &durable,
                    registry.expose(),
                    cfg.secret_authority_ttl,
                    cfg.secret_authority_hard_max,
                )
                .await
                .map_err(|error| WorkerError::Config(format!("secret registry is unavailable: {error}")))?;
                let custody = authority.custody();
                let mut stores =
                    Self::open_durable(cfg, durable, custody, keys, CustodyWrites::Required).await?;
                stores.secret_authority = Some(Arc::new(authority));
                stores.worker_lock = worker_lock;
                Ok(stores)
            }
        }
    }

    /// Open database stores that only read artifacts: reports and exports decrypt sealed
    /// artifacts through the catalog but never publish, so no secret registry is needed. A
    /// missing key provider leaves sealed artifacts unreadable with a clear error. A SQLite
    /// file that does not exist is an error, not a new database, and no worker lock is taken.
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
        let mut store_cfg = cfg.store.clone();
        store_cfg.create_if_missing = false;
        let database = Database::open(url, store_cfg).await?;
        let durable = DurableStore::open(&database)?;
        let custody = DurableAuthority::finalized_reads(&durable).custody();
        Self::open_durable(cfg, durable, custody, keys, CustodyWrites::ReadOnly).await
    }

    async fn open_durable(
        cfg: &WorkerConfig,
        durable: DurableStore,
        custody: Arc<dyn ArtifactCustody>,
        keys: Arc<dyn ArtifactKeys>,
        writes: CustodyWrites,
    ) -> Result<Self, WorkerError> {
        async fn artifact_store<B: Sql>(
            store: &Store<B>,
            choice: &ObjectStoreChoice,
            parts: ArtifactParts,
        ) -> Result<Arc<dyn ArtifactStore>, WorkerError> {
            let runs: Arc<dyn RunRepo> = Arc::new(store.clone());
            Ok(match choice {
                ObjectStoreChoice::Filesystem(dir) => Arc::new(
                    FsArtifactStore::open(dir, runs, parts.clock)
                        .await?
                        .with_index(Arc::new(store.clone()))
                        .with_zdr_buffer(parts.zdr)
                        .with_upload_spool(parts.spool)
                        .with_custody(parts.custody, parts.keys, parts.writes),
                ),
                ObjectStoreChoice::S3(config) => Arc::new(
                    S3ArtifactStore::new(
                        // the deployment id of the database claims the bucket prefix at the first write
                        S3Blobs::new(config)
                            .map_err(s3_error)?
                            .with_deployment(Arc::new(store.clone())),
                        runs,
                        parts.clock,
                    )
                    .with_index(Arc::new(store.clone()))
                    .with_zdr_buffer(parts.zdr)
                    .with_upload_spool(parts.spool)
                    .with_custody(parts.custody, parts.keys, parts.writes),
                ),
            })
        }
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let zdr = Arc::new(DeliveryBuffer::open_runtime(clock.clone(), BufferLimits::default()).await?);
        let durable = durable.with_delivery_buffer(zdr.clone());
        let spool = Arc::new(UploadSpool::new(cfg.artifact_spool.clone())?);
        let parts = ArtifactParts {
            clock,
            zdr,
            spool: spool.clone(),
            custody: Arc::clone(&custody),
            keys: Arc::clone(&keys),
            writes,
        };
        let choice = ObjectStoreChoice::from_lookup(&cfg.artifacts_dir, &|name| std::env::var(name).ok())?;
        let artifacts = crate::on_store!(&durable, store => artifact_store(store, &choice, parts).await?);
        let mut stores = Self::over_durable(durable, artifacts, TenantId::new());
        stores.delivery_spool = Some(spool);
        stores.custody = Some(custody);
        stores.artifact_keys = Some(keys);
        Ok(stores)
    }

    /// Stores over an already connected `durable` database of any engine.
    #[must_use]
    pub fn over_durable(durable: DurableStore, artifacts: Arc<dyn ArtifactStore>, tenant: TenantId) -> Self {
        fn repos<B: Sql>(
            store: &Store<B>,
            durable: DurableStore,
            artifacts: Arc<dyn ArtifactStore>,
            tenant: TenantId,
        ) -> Stores {
            let store = store.clone();
            Stores {
                runs: Arc::new(store.clone()),
                frontier: Arc::new(store.clone()),
                request_commits: Arc::new(store.clone()),
                approvals: Arc::new(store.clone()),
                report_history: Arc::new(store.clone()),
                url_graph: Arc::new(store.clone()),
                datasets: Arc::new(store.clone()),
                kv: Arc::new(store.clone()),
                source_memo: Arc::new(store.clone()),
                delivery: Arc::new(store.clone()),
                adaptive_selectors: Arc::new(store.clone()),
                archives: Arc::new(store.clone()),
                pages: Arc::new(store.clone()),
                journal: journal_with_failpoints(Arc::new(store.clone())),
                states: Arc::new(store.clone()),
                edges: Arc::new(store.clone()),
                ledger: Arc::new(store.clone()),
                audit: Arc::new(store.clone()),
                events: Arc::new(store.clone()),
                identity_aliases: Arc::new(store.clone()),
                model_decisions: Arc::new(store.clone()),
                leases: Arc::new(store.clone()),
                checkpoints: Arc::new(store),
                checkpoint_keys: Arc::new(crawlx_storage::checkpoint_crypto::UnavailableCheckpointKeys),
                artifacts,
                delivery_spool: None,
                custody: None,
                secret_authority: None,
                artifact_keys: None,
                tenant,
                memory: None,
                authorization: Some(Arc::new(DatabaseAuthorizationSource::new(durable.clone()))),
                origin_admission: Some(Arc::new(
                    durable.origin_admission(crawlx_fetch::GlobalOriginCap::DEFAULT_LIMIT),
                )),
                worker_lock: None,
                durable: Some(durable),
            }
        }
        crate::on_store!(&durable, store => repos(store, durable.clone(), artifacts, tenant))
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
            Some(admission) => Arc::new(crawlx_fetch::GlobalOriginCap::with_shared_admission(
                Arc::clone(&cfg.origin_cap),
                admission.for_run(cfg.origin_cap.limit(), run, per_run_limit),
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

/// What the artifact store of one engine is built from.
struct ArtifactParts {
    clock: Arc<dyn Clock>,
    zdr: Arc<DeliveryBuffer>,
    spool: Arc<UploadSpool>,
    custody: Arc<dyn ArtifactCustody>,
    keys: Arc<dyn ArtifactKeys>,
    writes: CustodyWrites,
}

/// Where a process keeps artifact objects: an S3-compatible bucket when `CRAWLX_S3_BUCKET` is
/// set (settings and `CRAWLX_S3_PROFILE` as in `docs/ops/object-storage.md`), otherwise the
/// filesystem root.
#[derive(Clone, Debug)]
pub enum ObjectStoreChoice {
    /// Objects under this directory.
    Filesystem(std::path::PathBuf),
    /// Objects in the bucket the configuration names.
    S3(S3Config),
}

impl ObjectStoreChoice {
    /// Choose from `get`, a lookup of environment variables; `dir` is the filesystem root used
    /// when no bucket is configured.
    ///
    /// # Errors
    /// [`WorkerError::Config`] when a bucket is named but the S3 settings are invalid.
    pub fn from_lookup(dir: &Path, get: &dyn Fn(&str) -> Option<String>) -> Result<Self, WorkerError> {
        if get("CRAWLX_S3_BUCKET").is_some_and(|bucket| !bucket.trim().is_empty()) {
            return S3Config::from_lookup(get).map(Self::S3).map_err(s3_error);
        }
        Ok(Self::Filesystem(dir.to_path_buf()))
    }

    /// Whether objects go to a bucket.
    #[must_use]
    pub const fn is_s3(&self) -> bool {
        matches!(self, Self::S3(_))
    }
}

fn s3_error(error: crawlx_storage::s3::S3ConfigError) -> WorkerError {
    WorkerError::Config(format!("object store: {error}"))
}

fn custody_error(error: impl std::fmt::Display) -> WorkerError {
    WorkerError::Config(format!("artifact key custody: {error}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn object_store_follows_the_bucket_setting() {
        let dir = Path::new("/tmp/artifacts");
        let none = |_: &str| None;
        assert!(matches!(
            ObjectStoreChoice::from_lookup(dir, &none).unwrap(),
            ObjectStoreChoice::Filesystem(path) if path == dir
        ));
        let blank = |name: &str| (name == "CRAWLX_S3_BUCKET").then(|| "  ".to_owned());
        assert!(!ObjectStoreChoice::from_lookup(dir, &blank).unwrap().is_s3());
        let s3 = |name: &str| match name {
            "CRAWLX_S3_BUCKET" => Some("b".to_owned()),
            "CRAWLX_S3_PROFILE" => Some("self-hosted".to_owned()),
            "CRAWLX_S3_ENDPOINT" => Some("http://127.0.0.1:9000".to_owned()),
            _ => None,
        };
        assert!(ObjectStoreChoice::from_lookup(dir, &s3).unwrap().is_s3());
        let bad = |name: &str| match name {
            "CRAWLX_S3_BUCKET" => Some("b".to_owned()),
            "CRAWLX_S3_PROFILE" => Some("compatible".to_owned()),
            _ => None,
        };
        assert!(
            ObjectStoreChoice::from_lookup(dir, &bad).is_err(),
            "compatible needs an endpoint"
        );
    }
}
