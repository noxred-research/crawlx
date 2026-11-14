//! Two products (or two CrawlX deployments) on one PostgreSQL server, each in its own schema:
//! each owns its tables and its migration ledger and neither sees the other's rows. Runs on
//! `CRAWLX_TEST_DATABASE_URL`; without it the test returns early.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::repo::RunRepo;
use crawlx_core::{CrawlRunId, StoreError};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{Pg, StoreConfig};
use sqlx::Row as _;

async fn connect(url: &str, schema: &str) -> Pg {
    let pg = Pg::connect(
        url,
        StoreConfig {
            schema: Some(schema.to_owned()),
            max_connections: 4,
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    pg
}

async fn tables(pg: &Pg, schema: &str, table: &str) -> i64 {
    sqlx::query(
        "SELECT count(*) AS n FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2",
    )
    .bind(schema)
    .bind(table)
    .fetch_one(pg.pool())
    .await
    .unwrap()
    .get("n")
}

#[tokio::test]
async fn schemas_keep_tables_migrations_and_rows_apart() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let unique = CrawlRunId::new().0.simple().to_string();
    let (name_a, name_b) = (format!("t_{unique}_a"), format!("t_{unique}_b"));
    let a = connect(&url, &name_a).await;
    let b = connect(&url, &name_b).await;
    for (pg, name) in [(&a, &name_a), (&b, &name_b)] {
        assert_eq!(tables(pg, name, "crawl_runs").await, 1, "{name} owns its tables");
        assert_eq!(
            tables(pg, name, "_sqlx_migrations").await,
            1,
            "{name} owns its migration ledger"
        );
    }
    let tenant = crawlx_core::TenantId::new();
    a.ensure_tenant(tenant, "schema-a").await.unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    RunRepo::create(&a, &run, None).await.unwrap();
    assert!(RunRepo::get(&a, run.id).await.is_ok());
    assert!(
        matches!(RunRepo::get(&b, run.id).await, Err(StoreError::NotFound { .. })),
        "the other schema does not see the run"
    );
    // a second connect to the first schema reuses its ledger instead of re-running migrations
    let again = connect(&url, &name_a).await;
    assert!(RunRepo::get(&again, run.id).await.is_ok());
    again.drop_schema().await.unwrap();
    b.drop_schema().await.unwrap();
}
