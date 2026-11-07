//! Verified authorization records for positive worker integration fixtures.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::repo::CrawlRun;
use crawlx_core::{Clock, CreateCrawl, SystemClock, TenantId};
use crawlx_policy::{testkit::sample_record, AuthorizationRecord};
use crawlx_worker::{AuthorizationGuard, LocalRun, RunReport, Stores, WorkerConfig, WorkerError};
use std::sync::Arc;

/// A verified record matching the fixture's selected ID, tenant and target.
pub fn verified_record(crawl: &CreateCrawl, tenant: TenantId) -> AuthorizationRecord {
    let now = SystemClock.now();
    let origin = crawl.seed_url.origin().ascii_serialization();
    let mut record = sample_record(tenant, now, &[&origin]);
    record.id = crawl
        .safety
        .authorization_record_ref
        .expect("fixture authorization reference");
    record.verified_at = Some(now);
    record.test_accounts = crawl
        .roles
        .iter()
        .filter_map(|role| {
            role.credential_ref
                .as_ref()
                .map(|reference| crawlx_policy::TestAccount {
                    role: role.name.clone(),
                    credential_ref: reference.0.clone(),
                })
        })
        .collect();
    if crawl.safety.allow_private_networks {
        record.authorized_networks = vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()];
        // Loopback fixtures may redirect between servers with different ephemeral ports.
        record.url_prefixes = vec!["http://127.0.0.1".to_owned(), "http://[::1]".to_owned()];
    }
    record
}

/// Run a positive fixture with its real verified authorization record installed.
/// Explicit authorization records and sources remain untouched, including refusal fixtures.
pub async fn run_authorized_local_with(mut local: LocalRun) -> Result<RunReport, WorkerError> {
    if local.cfg.checkpoint_keys.is_none()
        && local
            .stores
            .as_ref()
            .map_or(local.cfg.database_url.is_some(), |stores| {
                !stores.checkpoint_keys.is_available()
            })
    {
        local.cfg.checkpoint_keys = Some(Arc::new(
            crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap(),
        ));
    }
    if local.crawl.safety.authorization_record_ref.is_some()
        && local.authorization.is_none()
        && local.authorization_source.is_none()
        && local
            .stores
            .as_ref()
            .is_none_or(|stores| stores.authorization.is_none())
    {
        let stores = match local.stores.take() {
            Some(stores) => stores,
            None => Stores::open(&local.cfg).await?,
        };
        let record = verified_record(&local.crawl, stores.tenant);
        local = local.with_stores(stores).with_authorization(record);
    }
    crawlx_worker::run_local_with(local).await
}

/// The simple-run counterpart for positive fixtures.
pub async fn run_authorized_local(crawl: CreateCrawl, cfg: WorkerConfig) -> Result<RunReport, WorkerError> {
    run_authorized_local_with(LocalRun::new(crawl, cfg)).await
}

/// Admit a direct `RunContext` fixture through its installed authorization source.
pub async fn admit(stores: &Stores, run: &CrawlRun, cfg: &WorkerConfig) -> Arc<AuthorizationGuard> {
    AuthorizationGuard::admit(
        run.id,
        None,
        run.config.safety.authorization_record_ref,
        Arc::clone(
            stores
                .authorization
                .as_ref()
                .expect("fixture authorization source"),
        ),
        Arc::new(SystemClock),
        Arc::clone(&stores.events),
        cfg.authorization_recheck,
    )
    .await
    .unwrap()
}

/// Persist the fixture's verified lifecycle state as well as its immutable record body.
pub async fn register_verified(pg: &crawlx_storage::Pg, record: &AuthorizationRecord) {
    let body = serde_json::to_value(record).unwrap();
    let digest = record.body_digest().unwrap();
    pg.ensure_authorization_record(&crawlx_storage::AuthorizationRow {
        tenant: record.tenant,
        record: record.id,
        version: i32::try_from(record.version).unwrap(),
        body: &body,
        body_digest: &digest.0,
        valid_from: record.valid_from,
        valid_to: record.valid_to,
    })
    .await
    .unwrap();
    let at = record.verified_at.expect("verified fixture record");
    let proof = serde_json::json!({"kind": "test_fixture", "checkedAt": at});
    crawlx_storage::PgApiRepo::new(pg.clone())
        .authorization_mark_verified(record.tenant, record.id, &proof, at)
        .await
        .unwrap()
        .expect("registered fixture record");
}
