//! One durable database of any engine, as the worker and its callers hold it.
//!
//! The repository traits of `crawlx-storage` are implemented generically for
//! `Store<B>`; downstream code that needs a concrete handle (session bindings, secret
//! authority, deployment origin admission) holds one of these enums and runs generic
//! code through [`on_store!`](crate::on_store) / [`on_authority!`](crate::on_authority),
//! which expand to an exhaustive `match`. No caller outside `crawlx-storage` names an
//! engine otherwise.

use crawlx_core::origin::OriginAdmission;
use crawlx_core::session_binding::{SessionBindingV1, SessionIdentityV1};
use crawlx_core::{AuthorizationRecordId, CrawlRunId, StoreError, TenantId, Timestamp};
use crawlx_storage::backend::{
    BackendKind, BackendRefusal, Database, MariaBackend, PgBackend, SqliteBackend,
};
use crawlx_storage::custody::SecretAuthority;
use crawlx_storage::origin::{MariaOriginAdmission, PgOriginAdmission, SqliteOriginAdmission};
use crawlx_storage::session_binding::SessionBindingVerificationError;
use crawlx_storage::{ArtifactCustody, AuthorizationRow, DbArtifactCustody, Pg, SessionLease, Store};
use std::sync::Arc;
use std::time::Duration;

/// A connected store of whichever engine the database URL selected.
#[derive(Clone, Debug)]
pub enum DurableStore {
    /// PostgreSQL.
    Postgres(Pg),
    /// MariaDB.
    MariaDb(Store<MariaBackend>),
    /// SQLite.
    Sqlite(Store<SqliteBackend>),
}

/// Run `$body` with `$store` bound to the concrete `Store<B>` of a [`DurableStore`]
/// (taken by reference). The body is compiled once per engine, so it may call any
/// generic repository method.
#[macro_export]
macro_rules! on_store {
    ($durable:expr, $store:ident => $body:expr) => {
        match $durable {
            $crate::durable::DurableStore::Postgres($store) => $body,
            $crate::durable::DurableStore::MariaDb($store) => $body,
            $crate::durable::DurableStore::Sqlite($store) => $body,
        }
    };
}

/// Run `$body` with `$authority` bound to the concrete `SecretAuthority<B>` of a
/// [`DurableAuthority`] (taken by reference).
#[macro_export]
macro_rules! on_authority {
    ($durable:expr, $authority:ident => $body:expr) => {
        match $durable {
            $crate::durable::DurableAuthority::Postgres($authority) => $body,
            $crate::durable::DurableAuthority::MariaDb($authority) => $body,
            $crate::durable::DurableAuthority::Sqlite($authority) => $body,
        }
    };
}

impl DurableStore {
    /// The store of `database`.
    ///
    /// # Errors
    /// Returns the `backend_unimplemented` refusal for an engine this build has no
    /// repositories for.
    pub fn open(database: &Database) -> Result<Self, BackendRefusal> {
        if let Some(store) = database.as_postgres() {
            return Ok(Self::Postgres(store.clone()));
        }
        if let Some(store) = database.as_mariadb() {
            return Ok(Self::MariaDb(store.clone()));
        }
        if let Some(store) = database.as_sqlite() {
            return Ok(Self::Sqlite(store.clone()));
        }
        Err(BackendRefusal::unimplemented(
            database.kind(),
            crawlx_storage::Feature::Repositories.name(),
        ))
    }

    /// Which engine this is.
    #[must_use]
    pub const fn kind(&self) -> BackendKind {
        match self {
            Self::Postgres(_) => BackendKind::Postgres,
            Self::MariaDb(_) => BackendKind::MariaDb,
            Self::Sqlite(_) => BackendKind::Sqlite,
        }
    }

    /// This store with the volatile delivery buffer attached.
    #[must_use]
    pub fn with_delivery_buffer(self, delivery: Arc<crawlx_storage::DeliveryBuffer>) -> Self {
        match self {
            Self::Postgres(store) => Self::Postgres(store.with_delivery_buffer(delivery)),
            Self::MariaDb(store) => Self::MariaDb(store.with_delivery_buffer(delivery)),
            Self::Sqlite(store) => Self::Sqlite(store.with_delivery_buffer(delivery)),
        }
    }

    /// Journal transitions of `run`; see `ApiRepo::transitions_list`.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the read fails.
    pub async fn transitions_list(
        &self,
        run: CrawlRunId,
        filter: &crawlx_storage::TransitionFilter,
    ) -> Result<Vec<crawlx_storage::TransitionRecord>, StoreError> {
        crate::on_store!(self, store => crawlx_storage::ApiRepo::new(store.clone()).transitions_list(run, filter).await)
    }

    /// Tenant registration; see `Store::ensure_tenant`.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the write fails or the engine refuses a second tenant.
    pub async fn ensure_tenant(&self, tenant: TenantId, name: &str) -> Result<(), StoreError> {
        crate::on_store!(self, store => store.ensure_tenant(tenant, name).await)
    }

    /// Authorization record registration; see `Store::ensure_authorization_record`.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the writes fail.
    pub async fn ensure_authorization_record(&self, row: &AuthorizationRow<'_>) -> Result<(), StoreError> {
        crate::on_store!(self, store => store.ensure_authorization_record(row).await)
    }

    /// Bind a session identity under its live lease; see `Store::bind_session`.
    ///
    /// # Errors
    /// Returns lease loss, `session_unavailable` or a backend error.
    pub async fn bind_session(
        &self,
        lease: &SessionLease,
        identity: SessionIdentityV1,
        expires_at: Timestamp,
    ) -> Result<SessionBindingV1, StoreError> {
        crate::on_store!(self, store => store.bind_session(lease, identity, expires_at).await)
    }

    /// Compare-and-swap of binding lifecycle metadata; see `Store::update_session_binding`.
    ///
    /// # Errors
    /// Rejects stale fences, illegal transitions and expiry extension.
    pub async fn update_session_binding(
        &self,
        lease: &SessionLease,
        expected_version: u64,
        next: &SessionBindingV1,
    ) -> Result<(), StoreError> {
        crate::on_store!(self, store => store.update_session_binding(lease, expected_version, next).await)
    }

    /// Confirm lease and generation before a browser command; see `Store::verify_session_binding`.
    ///
    /// # Errors
    /// Store failures or typed binding ineligibility.
    pub async fn verify_session_binding(
        &self,
        lease: &SessionLease,
        binding: &SessionBindingV1,
    ) -> Result<(), SessionBindingVerificationError> {
        crate::on_store!(self, store => store.verify_session_binding(lease, binding).await)
    }

    /// Read the exact generation metadata; see `Store::load_session_binding`.
    ///
    /// # Errors
    /// Lease loss, missing binding or stale generation fence.
    pub async fn load_session_binding(
        &self,
        lease: &SessionLease,
        tenant: TenantId,
    ) -> Result<SessionBindingV1, StoreError> {
        crate::on_store!(self, store => store.load_session_binding(lease, tenant).await)
    }

    /// Replace a retired anonymous generation; see `Store::replace_retired_session_binding`.
    ///
    /// # Errors
    /// Lease/repository failures or a typed generation conflict.
    pub async fn replace_retired_session_binding(
        &self,
        lease: &SessionLease,
        expected: &SessionBindingV1,
        identity: SessionIdentityV1,
        expires_at: Timestamp,
    ) -> Result<SessionBindingV1, SessionBindingVerificationError> {
        crate::on_store!(self, store => store.replace_retired_session_binding(lease, expected, identity, expires_at).await)
    }

    /// Authorization record body; see `Store::authorization_record_body`.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the read fails.
    pub async fn authorization_record_body(
        &self,
        record: AuthorizationRecordId,
    ) -> Result<Option<serde_json::Value>, StoreError> {
        crate::on_store!(self, store => store.authorization_record_body(record).await)
    }

    /// The worker registry (registration, heartbeats, capability facts) of this database.
    #[must_use]
    pub fn worker_registry(&self) -> Arc<dyn crawlx_storage::WorkerRegistry> {
        crate::on_store!(self, store => Arc::new(store.clone()) as Arc<dyn crawlx_storage::WorkerRegistry>)
    }

    /// Deployment-wide origin admission over this database.
    #[must_use]
    pub fn origin_admission(&self, limit: usize) -> OriginAdmissions {
        match self {
            Self::Postgres(store) => OriginAdmissions::Postgres(PgOriginAdmission::new(store.clone(), limit)),
            Self::MariaDb(store) => OriginAdmissions::MariaDb(MariaOriginAdmission::new(store, limit)),
            Self::Sqlite(store) => OriginAdmissions::Sqlite(SqliteOriginAdmission::new(store, limit)),
        }
    }
}

/// The deployment's per-origin admission of one engine; clones share its pools.
#[derive(Clone, Debug)]
pub enum OriginAdmissions {
    /// PostgreSQL advisory-lock slots.
    Postgres(PgOriginAdmission),
    /// MariaDB row-lock slots.
    MariaDb(MariaOriginAdmission),
    /// SQLite slots with persisted pacing.
    Sqlite(SqliteOriginAdmission),
}

impl OriginAdmissions {
    /// Admission for one run: the deployment `limit` across runs and tenants plus the run's
    /// own `per_run_limit`.
    #[must_use]
    pub fn for_run(&self, limit: usize, run: CrawlRunId, per_run_limit: usize) -> Arc<dyn OriginAdmission> {
        match self {
            Self::Postgres(a) => Arc::new(a.clone().with_limit(limit).for_run(run, per_run_limit)),
            Self::MariaDb(a) => Arc::new(a.clone().with_limit(limit).for_run(run, per_run_limit)),
            Self::Sqlite(a) => Arc::new(a.clone().with_limit(limit).for_run(run, per_run_limit)),
        }
    }
}

/// The run-wide secret authority of one engine; clones share the database and the registry.
#[derive(Clone)]
pub enum DurableAuthority {
    /// PostgreSQL.
    Postgres(SecretAuthority<PgBackend>),
    /// MariaDB.
    MariaDb(SecretAuthority<MariaBackend>),
    /// SQLite.
    Sqlite(SecretAuthority<SqliteBackend>),
}

impl std::fmt::Debug for DurableAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableAuthority")
            .field("engine", &self.kind())
            .finish_non_exhaustive()
    }
}

impl DurableAuthority {
    /// Open renewable use windows over `store` and the persistence-free registry at
    /// `registry_url`.
    ///
    /// # Errors
    /// Rejects invalid windows, an inaccessible registry or a persistent registry.
    pub async fn open_with_policy(
        store: &DurableStore,
        registry_url: &str,
        ttl: Duration,
        hard_max: Duration,
    ) -> Result<Self, StoreError> {
        Ok(match store {
            DurableStore::Postgres(s) => Self::Postgres(
                SecretAuthority::open_with_policy(s.clone(), registry_url, ttl, hard_max).await?,
            ),
            DurableStore::MariaDb(s) => Self::MariaDb(
                SecretAuthority::open_with_policy(s.clone(), registry_url, ttl, hard_max).await?,
            ),
            DurableStore::Sqlite(s) => {
                Self::Sqlite(SecretAuthority::open_with_policy(s.clone(), registry_url, ttl, hard_max).await?)
            }
        })
    }

    /// Durable finalized reads only; no registry.
    #[must_use]
    pub fn finalized_reads(store: &DurableStore) -> Self {
        match store {
            DurableStore::Postgres(s) => Self::Postgres(SecretAuthority::finalized_reads(s.clone())),
            DurableStore::MariaDb(s) => Self::MariaDb(SecretAuthority::finalized_reads(s.clone())),
            DurableStore::Sqlite(s) => Self::Sqlite(SecretAuthority::finalized_reads(s.clone())),
        }
    }

    /// Which engine this is.
    #[must_use]
    pub const fn kind(&self) -> BackendKind {
        match self {
            Self::Postgres(_) => BackendKind::Postgres,
            Self::MariaDb(_) => BackendKind::MariaDb,
            Self::Sqlite(_) => BackendKind::Sqlite,
        }
    }

    /// This authority as the run-wide registry interface the privacy projections read through.
    #[must_use]
    pub fn run_authority(&self) -> Arc<dyn crawlx_core::custody::RunSecretAuthority> {
        crate::on_authority!(self, authority => {
            Arc::new(authority.clone()) as Arc<dyn crawlx_core::custody::RunSecretAuthority>
        })
    }

    /// The artifact custody that publishes and reads through this authority.
    #[must_use]
    pub fn custody(&self) -> Arc<dyn ArtifactCustody> {
        crate::on_authority!(self, authority => {
            Arc::new(DbArtifactCustody::new(authority.clone())) as Arc<dyn ArtifactCustody>
        })
    }
}

/// Refusal `sqlite_multi_tenant`: a staging or production SQLite deployment enforces tenant
/// isolation in the application only, so a second tenant needs
/// `CRAWLX_SQLITE_ALLOW_MULTI_TENANT=1`. `incoming` are the tenants about to be created.
///
/// # Errors
/// Returns the refusal as a [`StoreError`], or the error of the tenant count.
pub async fn check_sqlite_single_tenant(
    database: &Database,
    incoming: &[TenantId],
) -> Result<(), StoreError> {
    if database.kind() != BackendKind::Sqlite {
        return Ok(());
    }
    let guarded = std::env::var("CRAWLX_ENVIRONMENT")
        .is_ok_and(|environment| matches!(environment.as_str(), "staging" | "prod" | "production"));
    if !guarded || std::env::var("CRAWLX_SQLITE_ALLOW_MULTI_TENANT").as_deref() == Ok("1") {
        return Ok(());
    }
    let mut others = 0;
    if incoming.is_empty() {
        others = database.tenant_count_excluding(None).await?.saturating_sub(1);
    }
    for tenant in incoming {
        others += database.tenant_count_excluding(Some(*tenant)).await?;
    }
    if others > 0 || incoming.iter().collect::<std::collections::BTreeSet<_>>().len() > 1 {
        return Err(BackendRefusal::sqlite_multi_tenant().into());
    }
    Ok(())
}
