//! Host aliases that resolve to one address share one deployment cap across workers.
//!
//! Two governors, each over its own database handle and process-local queues, charge one
//! deployment admission store. The cap is one, the two origins are different host aliases of the
//! same address, and the second worker must wait for the first permit to drop. Runs on SQLite
//! always, and on PostgreSQL when `CRAWLX_TEST_DATABASE_URL` is set (PostgreSQL 14+).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_fetch::resolver::CheckedResolution;
use crawlx_fetch::{GlobalOriginCap, GovernorConfig, OriginGovernor, StaticResolver};
use crawlx_policy::EgressPolicy;
use crawlx_storage::{Database, OriginAdmissionFactory, StoreConfig};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use url::Url;

const DEADLINE: Duration = Duration::from_secs(20);

/// One worker: its own deployment admission handle, process-local caps and governor.
fn worker(database: &Database) -> OriginGovernor {
    let admission = database.origin_admission(1).expect("the engine shares admission");
    let cap = Arc::new(GlobalOriginCap::with_admission(1, admission));
    OriginGovernor::with_global_cap(
        GovernorConfig {
            base_delay: Duration::ZERO,
            ..GovernorConfig::default()
        },
        cap,
    )
}

async fn checked(host: &str, ip: IpAddr) -> CheckedResolution {
    CheckedResolution::resolve(
        &StaticResolver::new().with(host, [ip]),
        &EgressPolicy::new(false),
        &Url::parse(&format!("https://{host}/")).unwrap(),
    )
    .await
    .unwrap()
}

async fn aliases_share_the_cap(label: &str, first_database: &Database, second_database: &Database) {
    let first = worker(first_database);
    let second = worker(second_database);
    let ip = IpAddr::from([93, 184, 216, 34]);
    let a = checked(&format!("{label}-first.test"), ip).await;
    let b = checked(&format!("{label}-alias.test"), ip).await;
    let c = checked(&format!("{label}-third.test"), ip).await;
    let other = checked(&format!("{label}-other.test"), IpAddr::from([1, 1, 1, 1])).await;

    let held = first.acquire_resolved(a.origin(), &a).await.unwrap();
    // a different origin, the same machine: the second worker waits for the address
    assert!(
        timeout(
            Duration::from_millis(500),
            second.acquire_resolved(b.origin(), &b)
        )
        .await
        .is_err(),
        "{label}: an alias of a held address must wait"
    );
    // the abandoned wait released everything it had taken, and another address is not held back
    drop(
        timeout(DEADLINE, second.acquire_resolved(other.origin(), &other))
            .await
            .expect("another address is independent")
            .unwrap(),
    );
    drop(held);
    let admitted = timeout(DEADLINE, second.acquire_resolved(b.origin(), &b))
        .await
        .expect("the alias proceeds once the first permit dropped")
        .unwrap();
    // and the cap holds in the other direction while the second permit lives
    assert!(
        timeout(Duration::from_millis(500), first.acquire_resolved(c.origin(), &c))
            .await
            .is_err(),
        "{label}: a third alias must wait for the second worker's permit"
    );
    drop(admitted);
    drop(
        timeout(DEADLINE, first.acquire_resolved(c.origin(), &c))
            .await
            .expect("the address is free again")
            .unwrap(),
    );
}

#[tokio::test]
async fn sqlite_aliases_of_one_address_share_the_deployment_cap() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("crawlx.db").display());
    let first = Database::open(&url, StoreConfig::default()).await.unwrap();
    first.migrate().await.unwrap();
    let second = Database::open(&url, StoreConfig::default()).await.unwrap();
    aliases_share_the_cap("sqlite", &first, &second).await;
}

#[tokio::test]
async fn postgres_aliases_of_one_address_share_the_deployment_cap() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let schema = format!("t_{}", crawlx_core::CrawlRunId::new().0.simple());
    let open = || {
        Database::open(
            &url,
            StoreConfig {
                schema: Some(schema.clone()),
                max_connections: 4,
                ..StoreConfig::default()
            },
        )
    };
    let first = open().await.unwrap();
    first.migrate().await.unwrap();
    let second = open().await.unwrap();
    aliases_share_the_cap("postgres", &first, &second).await;
}
